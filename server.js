const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json({ limit: "40kb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 10000;
const ADMIN_CODE = process.env.ADMIN_CODE || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

function configReady() {
  return Boolean(ADMIN_CODE && SESSION_SECRET && SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function makeCookieToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + sig;
}
function isAdmin(req) {
  if (!SESSION_SECRET) return false;
  const cookies = Object.fromEntries((req.headers.cookie || "").split(";").map(x => x.trim()).filter(Boolean).map(x => {
    const i = x.indexOf("=");
    return [x.slice(0, i), decodeURIComponent(x.slice(i + 1))];
  }));
  const parts = (cookies.tc_admin || "").split(".");
  if (parts.length !== 2) return false;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(parts[0]).digest("base64url");
  if (!safeEqual(parts[1], expected)) return false;
  try {
    return JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")).exp > Date.now();
  } catch (_) { return false; }
}
async function dbRequest(endpoint, options = {}) {
  const response = await fetch(SUPABASE_URL + "/rest/v1/" + endpoint, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await response.text();
  if (!response.ok) throw new Error("Database error " + response.status);
  return body ? JSON.parse(body) : null;
}

app.get("/api/status", (req, res) => res.json({ ready: configReady() }));

app.post("/api/submit", async (req, res) => {
  try {
    if (!configReady()) return res.status(503).json({ error: "Сайт ещё не настроен администратором." });
    const body = req.body || {};
    if (!Array.isArray(body.answers) || body.answers.length !== 24) {
      return res.status(400).json({ error: "Нужно ответить на все 24 вопроса." });
    }
    const answers = body.answers.map((item, index) => {
      if (!item || !["yes", "no", "custom"].includes(item.choice)) throw new Error("Некорректный ответ.");
      const note = typeof item.note === "string" ? item.note.trim().slice(0, 500) : "";
      if (item.choice === "custom" && !note) throw new Error("Заполни свой вариант в вопросе " + (index + 1) + ".");
      return { question: index + 1, choice: item.choice, note };
    });
    const nickname = typeof body.nickname === "string" ? body.nickname.trim().slice(0, 24) : "";
    const scored = answers.filter(x => x.choice === "yes" || x.choice === "no");
    const yesCount = scored.filter(x => x.choice === "yes").length;
    const customCount = answers.length - scored.length;
    const score = scored.length ? Math.round(yesCount / scored.length * 100) : null;
    const categoryScores = [];
    const categoryNames = ["Честность", "Уважение границ", "Ответственность", "Надёжность"];
    for (let category = 0; category < 4; category++) {
      const group = scored.filter(x => x.question > category * 6 && x.question <= (category + 1) * 6);
      const groupYes = group.filter(x => x.choice === "yes").length;
      categoryScores.push({
        name: categoryNames[category],
        score: group.length ? Math.round(groupYes / group.length * 100) : null,
        answered: group.length
      });
    }
    await dbRequest("trust_submissions", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify({
        nickname, answers, score,
        scored_answers: scored.length,
        custom_answers: customCount,
        category_scores: categoryScores
      })
    });
    res.json({ ok: true, score, scoredAnswers: scored.length, customAnswers: customCount, categoryScores });
  } catch (error) {
    res.status(400).json({ error: error.message || "Не удалось сохранить ответы." });
  }
});

app.post("/api/admin/login", (req, res) => {
  if (!configReady()) return res.status(503).json({ error: "Сервер ещё не настроен." });
  if (!safeEqual(String((req.body || {}).code || ""), ADMIN_CODE)) {
    return res.status(401).json({ error: "Неверный код." });
  }
  res.setHeader("Set-Cookie", "tc_admin=" + encodeURIComponent(makeCookieToken()) + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800");
  res.json({ ok: true });
});
app.post("/api/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "tc_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
  res.json({ ok: true });
});
app.get("/api/admin/results", async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: "Нужен вход администратора." });
  try {
    const rows = await dbRequest("trust_submissions?select=id,created_at,nickname,answers,score,scored_answers,custom_answers,category_scores&order=created_at.desc&limit=500");
    res.json({ results: rows });
  } catch (_) {
    res.status(500).json({ error: "Не удалось загрузить результаты. Проверь базу данных." });
  }
});
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, "0.0.0.0", () => console.log("TRUST CHECK 2.0 listening on " + PORT));
