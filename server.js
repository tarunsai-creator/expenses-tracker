const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "100kb" }));
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || !process.env.DATABASE_URL) {
  console.error("DATABASE_URL and JWT_SECRET environment variables are required.");
  process.exit(1);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS categories (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      UNIQUE(user_id, name)
    );
    CREATE TABLE IF NOT EXISTS methods (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      UNIQUE(user_id, name)
    );
    CREATE TABLE IF NOT EXISTS expenses (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      spent_on DATE NOT NULL,
      category_id BIGINT NOT NULL REFERENCES categories(id),
      method_id BIGINT NOT NULL REFERENCES methods(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS budgets (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      category_id BIGINT NOT NULL REFERENCES categories(id),
      month TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      UNIQUE(user_id, category_id, month)
    );
  `);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = Number(payload.sub);
    if (!Number.isSafeInteger(req.userId)) throw new Error("Invalid user");
    next();
  } catch {
    res.status(401).json({ error: "Please log in again." });
  }
}
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6) {
    return res.status(400).json({ error: "Enter your name, a valid email, and a password of at least 6 characters." });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email",
      [name, email, passwordHash]
    );
    const user = result.rows[0];
    for (const category of ["Food", "Travel", "Shopping", "Bills", "Health", "Other"]) {
      await client.query("INSERT INTO categories(user_id,name) VALUES($1,$2)", [user.id, category]);
    }
    for (const method of ["Cash", "UPI", "Card"]) {
      await client.query("INSERT INTO methods(user_id,name) VALUES($1,$2)", [user.id, method]);
    }
    await client.query("COMMIT");
    const token = jwt.sign({}, JWT_SECRET, { subject: String(user.id), expiresIn: "14d" });
    res.status(201).json({ token, user: { name: user.name, email: user.email } });
  } catch (e) {
    await client.query("ROLLBACK");
    if (e.code === "23505") return res.status(409).json({ error: "Email already registered." });
    throw e;
  } finally {
    client.release();
  }
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const result = await pool.query("SELECT id,name,email,password_hash FROM users WHERE email=$1", [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  const token = jwt.sign({}, JWT_SECRET, { subject: String(user.id), expiresIn: "14d" });
  res.json({ token, user: { name: user.name, email: user.email } });
}));

app.use("/api", auth);

app.get("/api/profile", asyncRoute(async (req, res) => {
  const r = await pool.query("SELECT name,email FROM users WHERE id=$1", [req.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "User not found." });
  res.json(r.rows[0]);
}));
app.put("/api/profile", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name) return res.status(400).json({ error: "Name is required." });
  const r = await pool.query("UPDATE users SET name=$1 WHERE id=$2 RETURNING name,email", [name, req.userId]);
  res.json(r.rows[0]);
}));

for (const [route, table] of [["categories","categories"],["methods","methods"]]) {
  app.get(`/api/${route}`, asyncRoute(async (req, res) => {
    const r = await pool.query(`SELECT id,name FROM ${table} WHERE user_id=$1 ORDER BY id`, [req.userId]);
    res.json(r.rows);
  }));
  app.post(`/api/${route}`, asyncRoute(async (req, res) => {
    const name = String(req.body.name || "").trim();
    if (!name || name.length > 40) return res.status(400).json({ error: "Enter a name up to 40 characters." });
    try {
      const r = await pool.query(`INSERT INTO ${table}(user_id,name) VALUES($1,$2) RETURNING id,name`, [req.userId,name]);
      res.status(201).json(r.rows[0]);
    } catch (e) {
      if (e.code === "23505") return res.status(409).json({ error: "Already exists." });
      throw e;
    }
  }));
  app.delete(`/api/${route}/:id`, asyncRoute(async (req, res) => {
    const r = await pool.query(`DELETE FROM ${table} WHERE id=$1 AND user_id=$2 RETURNING id`, [req.params.id,req.userId]);
    if (!r.rowCount) return res.status(404).json({ error: "Not found." });
    res.json({ ok: true });
  }));
}

app.get("/api/expenses", asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT e.id,e.description,e.amount,e.spent_on::text,e.category_id,e.method_id
     FROM expenses e WHERE e.user_id=$1 ORDER BY e.spent_on DESC,e.id DESC`, [req.userId]);
  res.json(r.rows);
}));
app.post("/api/expenses", asyncRoute(async (req, res) => {
  const { description, amount, spent_on, category_id, method_id } = req.body;
  const value = Number(amount);
  if (!String(description || "").trim() || String(description).length > 60 ||
      !Number.isFinite(value) || value <= 0 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(String(spent_on || ""))) {
    return res.status(400).json({ error: "Check the description, amount, and date." });
  }
  const owned = await pool.query(
    `SELECT 1 FROM categories c JOIN methods m ON m.user_id=c.user_id
     WHERE c.id=$1 AND c.user_id=$2 AND m.id=$3 AND m.user_id=$2`,
    [category_id, req.userId, method_id]);
  if (!owned.rowCount) return res.status(400).json({ error: "Choose a valid category and payment method." });
  const r = await pool.query(
    `INSERT INTO expenses(user_id,description,amount,spent_on,category_id,method_id)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING id,description,amount,spent_on::text,category_id,method_id`,
    [req.userId,String(description).trim(),value,spent_on,category_id,method_id]);
  res.status(201).json(r.rows[0]);
}));
app.delete("/api/expenses/:id", asyncRoute(async (req, res) => {
  const r = await pool.query("DELETE FROM expenses WHERE id=$1 AND user_id=$2 RETURNING id", [req.params.id,req.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "Not found." });
  res.json({ ok: true });
}));

app.get("/api/budgets", asyncRoute(async (req, res) => {
  const r = await pool.query("SELECT id,category_id,month,amount FROM budgets WHERE user_id=$1 ORDER BY month DESC,id", [req.userId]);
  res.json(r.rows);
}));
app.post("/api/budgets", asyncRoute(async (req, res) => {
  const { category_id, month, amount } = req.body;
  const value = Number(amount);
  if (!/^\d{4}-\d{2}$/.test(String(month || "")) || !Number.isFinite(value) || value <= 0) {
    return res.status(400).json({ error: "Enter a valid month and positive budget." });
  }
  const r = await pool.query(
    `INSERT INTO budgets(user_id,category_id,month,amount)
     SELECT $1,c.id,$3,$4 FROM categories c WHERE c.id=$2 AND c.user_id=$1
     ON CONFLICT(user_id,category_id,month) DO UPDATE SET amount=EXCLUDED.amount
     RETURNING id,category_id,month,amount`,
    [req.userId,category_id,month,value]);
  if (!r.rowCount) return res.status(400).json({ error: "Choose a valid category." });
  res.json(r.rows[0]);
}));
app.delete("/api/budgets/:id", asyncRoute(async (req, res) => {
  const r = await pool.query("DELETE FROM budgets WHERE id=$1 AND user_id=$2 RETURNING id", [req.params.id,req.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "Not found." });
  res.json({ ok: true });
}));

app.get("/api/reports/monthly", asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT TO_CHAR(spent_on,'YYYY-MM') AS label, SUM(amount)::numeric AS total
     FROM expenses WHERE user_id=$1 GROUP BY 1 ORDER BY 1`, [req.userId]);
  res.json(r.rows);
}));
app.get("/api/reports/by-category", asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT c.name AS label, SUM(e.amount)::numeric AS total
     FROM expenses e JOIN categories c ON c.id=e.category_id
     WHERE e.user_id=$1 GROUP BY c.name ORDER BY total DESC`, [req.userId]);
  res.json(r.rows);
}));

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error. Please try again." });
});

const port = process.env.PORT || 3000;
initDb().then(() => app.listen(port, "0.0.0.0", () => console.log(`Expense Tracker listening on ${port}`)))
  .catch(err => { console.error("Database initialization failed:", err); process.exit(1); });
