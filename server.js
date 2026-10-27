require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  },
  credentials: false
}));

const port = Number(process.env.PORT || 3000);
const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

let db;
if (supabaseUrl && serviceRoleKey) {
  db = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
}

function requireDb(req, res, next) {
  if (!db) {
    return res.status(503).json({
      error: "Backend is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the hosting environment."
    });
  }
  next();
}

async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Please sign in first." });

  const { data, error } = await db.auth.getUser(token);
  if (error || !data?.user) {
    return res.status(401).json({ error: "Your session is invalid or expired." });
  }
  req.user = data.user;
  next();
}

async function requireAdmin(req, res, next) {
  const { data, error } = await db
    .from("profiles")
    .select("is_admin")
    .eq("id", req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: "Could not verify administrator access." });
  if (!data?.is_admin) return res.status(403).json({ error: "Administrator access required." });
  next();
}

app.get("/", (_req, res) => {
  res.json({ name: "DeeBlaq's Market API", status: "running" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/categories", requireDb, async (_req, res) => {
  const { data, error } = await db
    .from("categories")
    .select("id,name,sort,is_active")
    .eq("is_active", true)
    .order("sort", { ascending: true });

  if (error) return res.status(500).json({ error: "Could not load categories." });
  res.json({ categories: data || [] });
});

app.get("/api/products", requireDb, async (req, res) => {
  let query = db
    .from("products")
    .select("id,category_id,name,price,image_url,description,available,is_active,created_at")
    .eq("is_active", true)
    .eq("available", true)
    .order("created_at", { ascending: false });

  if (req.query.category_id) query = query.eq("category_id", req.query.category_id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: "Could not load products." });
  res.json({ products: data || [] });
});

app.post("/api/auth/signup", requireDb, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email || !email.includes("@") || password.length < 8) {
    return res.status(400).json({ error: "Enter a valid email and a password of at least 8 characters." });
  }

  const { data, error } = await db.auth.admin.createUser({
    email,
    password,
    email_confirm: false
  });
  if (error) return res.status(400).json({ error: error.message });

  const { error: profileError } = await db.from("profiles").upsert({
    id: data.user.id,
    email,
    balance: 0,
    is_admin: false
  }, { onConflict: "id" });

  if (profileError) {
    await db.auth.admin.deleteUser(data.user.id);
    return res.status(500).json({ error: "Could not create the customer profile." });
  }

  res.status(201).json({
    message: "Account created. Check your email if email confirmation is enabled.",
    user: { id: data.user.id, email: data.user.email }
  });
});

app.post("/api/auth/login", requireDb, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

  const { data, error } = await db.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: "Email or password is incorrect." });

  res.json({
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_at: data.session.expires_at,
    user: { id: data.user.id, email: data.user.email }
  });
});

app.get("/api/me", requireDb, authenticate, async (req, res) => {
  const { data, error } = await db
    .from("profiles")
    .select("id,email,balance,is_admin")
    .eq("id", req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: "Could not load profile." });
  res.json({ user: { id: req.user.id, email: req.user.email }, profile: data });
});

/*
 * Safety note:
 * Wallet credits, payment verification, order fulfilment, and admin changes
 * are intentionally not implemented as unverified shortcuts. Add these only
 * after the payment provider and inventory/delivery rules are defined.
 */
app.use((err, _req, res, _next) => {
  console.error(err?.message || "Unexpected server error");
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(port, () => {
  console.log(`DeeBlaq's Market API listening on port ${port}`);
});
