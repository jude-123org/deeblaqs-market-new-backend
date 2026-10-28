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

const ok = (res, error, data, msg = "Request failed.") =>
  error ? res.status(500).json({ error: msg }) : res.json(data);
const admin = [requireDb, authenticate, requireAdmin];
const pick = (b, keys) => Object.fromEntries(keys.filter((k) => b?.[k] !== undefined).map((k) => [k, b[k]]));
const cleanProduct = (b) => {
  const d = pick(b, ["category_id", "name", "price", "image_url", "description", "available"]);
  if (d.name !== undefined) d.name = String(d.name).trim().slice(0, 120);
  if (d.price !== undefined) d.price = Number(d.price);
  if (d.image_url !== undefined) d.image_url = String(d.image_url).trim().slice(0, 500);
  if (d.description !== undefined) d.description = String(d.description).slice(0, 500);
  return d;
};

/* ---------- Admin: products ---------- */
app.get("/api/admin/products", admin, async (_req, res) => {
  const { data, error } = await db.from("products").select("*").eq("is_active", true).order("created_at", { ascending: false });
  ok(res, error, { products: data || [] }, "Could not load products.");
});
app.post("/api/admin/products", admin, async (req, res) => {
  const d = cleanProduct(req.body);
  if (!d.name || !(d.price >= 0)) return res.status(400).json({ error: "Name and a valid price are required." });
  const { data, error } = await db.from("products").insert({ available: true, is_active: true, ...d }).select().single();
  ok(res, error, { product: data }, "Could not save product.");
});
app.put("/api/admin/products/:id", admin, async (req, res) => {
  const d = cleanProduct(req.body);
  if (d.price !== undefined && !(d.price >= 0)) return res.status(400).json({ error: "Invalid price." });
  const { data, error } = await db.from("products").update(d).eq("id", req.params.id).select().single();
  ok(res, error, { product: data }, "Could not update product.");
});
app.delete("/api/admin/products/:id", admin, async (req, res) => {
  const { error } = await db.from("products").update({ is_active: false }).eq("id", req.params.id);
  ok(res, error, { deleted: true }, "Could not delete product.");
});

/* ---------- Admin: categories ---------- */
app.post("/api/admin/categories", admin, async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: "Category name required." });
  const { data, error } = await db.from("categories").insert({ name, sort: Number(req.body?.sort) || 0, is_active: true }).select().single();
  ok(res, error, { category: data }, "Could not save category.");
});
app.put("/api/admin/categories/:id", admin, async (req, res) => {
  const d = pick(req.body, ["name", "sort"]);
  const { data, error } = await db.from("categories").update(d).eq("id", req.params.id).select().single();
  ok(res, error, { category: data }, "Could not update category.");
});
app.delete("/api/admin/categories/:id", admin, async (req, res) => {
  const { error } = await db.from("categories").update({ is_active: false }).eq("id", req.params.id);
  ok(res, error, { deleted: true }, "Could not delete category.");
});

/* ---------- Customer: deposits ---------- */
app.post("/api/deposits", requireDb, authenticate, async (req, res) => {
  const amount = Number(req.body?.amount), reference = String(req.body?.reference || "").trim().slice(0, 120);
  if (!(amount > 0) || !reference) return res.status(400).json({ error: "Amount and payment reference are required." });
  const { data, error } = await db.from("deposits").insert({ user_id: req.user.id, amount, reference, status: "pending" }).select().single();
  ok(res, error, { deposit: data }, "Could not submit deposit.");
});
app.get("/api/deposits", requireDb, authenticate, async (req, res) => {
  const { data, error } = await db.from("deposits").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
  ok(res, error, { deposits: data || [] }, "Could not load deposits.");
});

/* ---------- Customer: orders (paid from wallet, atomic) ---------- */
app.post("/api/orders", requireDb, authenticate, async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 50) : [];
  if (!items.length) return res.status(400).json({ error: "Your cart is empty." });
  const ids = items.map((i) => i.product_id);
  const { data: prods, error } = await db.from("products").select("id,name,price").in("id", ids).eq("is_active", true).eq("available", true);
  if (error) return res.status(500).json({ error: "Could not check products." });
  let total = 0; const lines = [];
  for (const i of items) {
    const p = (prods || []).find((x) => x.id === i.product_id);
    const qty = Math.max(1, Math.min(20, parseInt(i.qty, 10) || 1));
    if (!p) return res.status(400).json({ error: "A product in your cart is no longer available." });
    total += Number(p.price) * qty; lines.push({ product_id: p.id, name: p.name, price: p.price, qty });
  }
  const { error: rpcErr } = await db.rpc("place_order", { p_user: req.user.id, p_items: lines, p_total: total });
  if (rpcErr) return res.status(400).json({ error: /insufficient/i.test(rpcErr.message) ? "Insufficient balance. Deposit funds first." : "Could not place order." });
  res.status(201).json({ ok: true, total });
});
app.get("/api/orders", requireDb, authenticate, async (req, res) => {
  const { data, error } = await db.from("orders").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
  ok(res, error, { orders: data || [] }, "Could not load orders.");
});

/* ---------- Admin: deposits & orders ---------- */
app.get("/api/admin/deposits", admin, async (_req, res) => {
  const { data, error } = await db.from("deposits").select("*").order("created_at", { ascending: false }).limit(200);
  ok(res, error, { deposits: data || [] }, "Could not load deposits.");
});
app.post("/api/admin/deposits/:id/approve", admin, async (req, res) => {
  const { error } = await db.rpc("approve_deposit", { p_id: req.params.id });
  ok(res, error, { approved: true }, "Could not approve (already handled?).");
});
app.post("/api/admin/deposits/:id/reject", admin, async (req, res) => {
  const { error } = await db.from("deposits").update({ status: "rejected" }).eq("id", req.params.id).eq("status", "pending");
  ok(res, error, { rejected: true }, "Could not reject.");
});
app.get("/api/admin/orders", admin, async (_req, res) => {
  const { data, error } = await db.from("orders").select("*").order("created_at", { ascending: false }).limit(200);
  ok(res, error, { orders: data || [] }, "Could not load orders.");
});
app.put("/api/admin/orders/:id/deliver", admin, async (req, res) => {
  const { error } = await db.from("orders").update({ status: "delivered" }).eq("id", req.params.id);
  ok(res, error, { delivered: true }, "Could not update order.");
});

app.use((err, _req, res, _next) => {
  console.error(err?.message || "Unexpected server error");
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(port, () => {
  console.log(`DeeBlaq's Market API listening on port ${port}`);
});
