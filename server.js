require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);
app.use(helmet());
/* Deposits can carry a receipt screenshot, so this route accepts a larger body.
   It must come before the global parser below. */
app.use("/api/deposits", express.json({ limit: "1mb" }));
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
/* remove accidental spaces or quotes around the hosting values */
const cleanEnv = (v) => String(v || "").trim().replace(/^["']|["']$/g, "");
const supabaseUrl = cleanEnv(process.env.SUPABASE_URL);
const serviceRoleKey = cleanEnv(process.env.SUPABASE_SERVICE_ROLE_KEY);

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
  /* shows only true/false, never the values */
  res.json({ ok: true, has_url: Boolean(supabaseUrl), has_service_key: Boolean(serviceRoleKey), configured: Boolean(db) });
});

app.get("/api/categories", requireDb, authenticate, async (_req, res) => {
  const { data, error } = await db
    .from("categories")
    .select("id,name,sort,is_active")
    .eq("is_active", true)
    .order("sort", { ascending: true });

  if (error) return res.status(500).json({ error: "Could not load categories." });
  res.json({ categories: data || [] });
});

const san = (v) => String(v || "").replace(/[%,()*\\]/g, " ").trim().slice(0, 60);
const pageOf = (req, size) => { const page = Math.max(1, parseInt(req.query.page, 10) || 1); const from = (page - 1) * size; return { page, from, to: from + size - 1 }; };
async function stockInfo(ids) {
  const map = {};
  if (!ids.length) return map;
  const { data } = await db.from("stock_summary").select("product_id,plan,available").in("product_id", ids);
  (data || []).forEach((r) => { (map[r.product_id] = map[r.product_id] || {})[r.plan || ""] = r.available; });
  return map;
}
app.get("/api/products", requireDb, authenticate, async (req, res) => {
  const size = 24;
  const { from, to } = pageOf(req, size);
  let query = db
    .from("products")
    .select("id,category_id,name,price,image_url,description,available,is_active,plans,quantity,created_at")
    .eq("is_active", true)
    .eq("available", true)
    .order("created_at", { ascending: false })
    .range(from, to + 1);
  if (req.query.category_id) query = query.eq("category_id", req.query.category_id);
  const q = san(req.query.q);
  if (q) query = query.ilike("name", "%" + q + "%");
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: "Could not load products." });
  const list = (data || []).slice(0, size);
  const info = await stockInfo(list.map((p) => String(p.id)));
  res.json({ products: list.map((p) => ({ ...p, by_plan: info[String(p.id)] || null })), more: (data || []).length > size });
});

const authClient = () =>
  createClient(supabaseUrl, serviceRoleKey, { auth: { autoRefreshToken: false, persistSession: false } });
const hits = new Map();
function limited(key, max = 5, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(key, list);
  return list.length > max;
}
const strongPassword = (p) => p.length >= 8 && p.length <= 72 && /[A-Za-z]/.test(p) && /\d/.test(p);
const PASS_MSG = "Password must be at least 8 characters and include both letters and numbers.";
const cleanEmail = (v) => String(v || "").trim().toLowerCase();

app.post("/api/auth/signup", requireDb, async (req, res) => {
  const first = String(req.body?.first_name || "").trim().slice(0, 60);
  const last = String(req.body?.last_name || "").trim().slice(0, 60);
  const phone = String(req.body?.phone || "").trim().replace(/[\s-]/g, "");
  const email = cleanEmail(req.body?.email);
  const password = String(req.body?.password || "");
  if (!first || !last) return res.status(400).json({ error: "First name and last name are required." });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (phone && !/^\+?\d{7,15}$/.test(phone)) return res.status(400).json({ error: "Enter a valid phone number or leave it empty." });
  if (!strongPassword(password)) return res.status(400).json({ error: PASS_MSG });

  const { data, error } = await db.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { first_name: first, last_name: last, phone: phone || null }
  });
  if (error) {
    const exists = /already|registered|exists/i.test(error.message);
    return res.status(400).json({ error: exists ? "An account with this email already exists." : error.message });
  }

  const { error: profileError } = await db.from("profiles").upsert({
    id: data.user.id,
    email,
    first_name: first,
    last_name: last,
    phone: phone || null,
    balance: 0,
    is_admin: false
  }, { onConflict: "id" });

  if (profileError) {
    await db.auth.admin.deleteUser(data.user.id);
    return res.status(500).json({ error: "Could not create the customer profile." });
  }
  res.status(201).json({ message: "Account created. You can log in now.", user: { id: data.user.id, email } });
});

app.post("/api/auth/login", requireDb, async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const password = String(req.body?.password || "");
  if (!email || !password) return res.status(400).json({ error: "Email and password are required." });
  if (limited("l:" + email, 10)) return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });

  const { data, error } = await authClient().auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: "Email or password is incorrect." });

  res.json({
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_at: data.session.expires_at,
    user: { id: data.user.id, email: data.user.email }
  });
});

/* Forgot password: step 1 sends a code to the email, step 2 checks it and sets a new password */
app.post("/api/auth/forgot", requireDb, async (req, res) => {
  const email = cleanEmail(req.body?.email);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (limited("f:" + email, 3) || limited("fi:" + req.ip, 10)) {
    return res.status(429).json({ error: "Too many requests. Try again in a few minutes." });
  }
  await authClient().auth.resetPasswordForEmail(email);
  res.json({ message: "If this email has an account, a code has been sent. Check your inbox and spam." });
});

app.post("/api/auth/reset", requireDb, async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const code = String(req.body?.code || "").trim();
  const password = String(req.body?.password || "");
  if (!/^\d{6,10}$/.test(code)) return res.status(400).json({ error: "Enter the numeric code from your email." });
  if (!strongPassword(password)) return res.status(400).json({ error: PASS_MSG });
  if (limited("r:" + email, 5)) return res.status(429).json({ error: "Too many attempts. Request a new code later." });

  const { data, error } = await authClient().auth.verifyOtp({ email, token: code, type: "recovery" });
  if (error || !data?.user) return res.status(400).json({ error: "The code is wrong or has expired." });

  const { error: updateError } = await db.auth.admin.updateUserById(data.user.id, { password });
  if (updateError) return res.status(500).json({ error: "Could not set the new password." });
  res.json({ message: "Password changed. You can log in now." });
});

app.get("/api/me", requireDb, authenticate, async (req, res) => {
  const { data, error } = await db
    .from("profiles")
    .select("id,email,first_name,last_name,phone,balance,is_admin")
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
  if (b?.plans !== undefined) {
    const arr = Array.isArray(b.plans) ? b.plans : [];
    d.plans = arr.slice(0, 10)
      .map((p) => ({ label: String(p?.label || "").trim().slice(0, 40), price: Number(p?.price) }))
      .filter((p) => p.label && p.price >= 0);
    if (d.plans.length) d.price = Math.min(...d.plans.map((p) => p.price));
  }
  if (b?.quantity !== undefined) {
    const n = b.quantity === "" || b.quantity === null ? null : Math.max(0, Math.floor(Number(b.quantity)));
    d.quantity = Number.isFinite(n) ? n : null;
  }
  return d;
};

/* ---------- Admin: products ---------- */
app.get("/api/admin/products", admin, async (req, res) => {
  const size = 50;
  const { from, to } = pageOf(req, size);
  let query = db.from("products").select("*").eq("is_active", true).order("created_at", { ascending: false }).range(from, to + 1);
  const q = san(req.query.q);
  if (q) query = query.ilike("name", "%" + q + "%");
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: "Could not load products." });
  res.json({ products: (data || []).slice(0, size), more: (data || []).length > size });
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
const RECEIPT_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
app.post("/api/deposits", requireDb, authenticate, async (req, res) => {
  const amount = Number(req.body?.amount), reference = String(req.body?.reference || "").trim().slice(0, 120);
  if (!(amount > 0) || !reference) return res.status(400).json({ error: "Amount and payment reference are required." });
  const receipt = req.body?.receipt ? String(req.body.receipt) : "";
  if (receipt && (receipt.length > 800000 || !RECEIPT_RE.test(receipt))) {
    return res.status(400).json({ error: "The receipt image is invalid or too large. Please try a smaller screenshot." });
  }
  const { data, error } = await db.from("deposits").insert({ user_id: req.user.id, amount, reference, status: "pending" }).select().single();
  if (error) return res.status(500).json({ error: "Could not submit deposit." });
  if (receipt) {
    const { error: rErr } = await db.from("deposit_receipts").insert({ deposit_id: String(data.id), image: receipt });
    if (rErr) {
      await db.from("deposits").delete().eq("id", data.id).eq("status", "pending");
      return res.status(500).json({ error: "Could not save your receipt. Please try again." });
    }
  }
  res.json({ deposit: data });
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
  const { data: prods, error } = await db.from("products").select("id,name,price,plans").in("id", ids).eq("is_active", true).eq("available", true);
  if (error) return res.status(500).json({ error: "Could not check products." });
  let total = 0; const lines = [];
  for (const i of items) {
    const p = (prods || []).find((x) => String(x.id) === String(i.product_id));
    const qty = Math.max(1, Math.min(20, parseInt(i.qty, 10) || 1));
    if (!p) return res.status(400).json({ error: "A product in your cart is no longer available." });
    let price = Number(p.price), name = p.name;
    const plans = Array.isArray(p.plans) ? p.plans : [];
    if (plans.length) {
      const plan = plans.find((x) => x.label === i.plan);
      if (!plan) return res.status(400).json({ error: "Please choose a plan for " + p.name + "." });
      price = Number(plan.price); name = p.name + " (" + plan.label + ")";
    }
    total += price * qty; lines.push({ product_id: p.id, name, price, qty, plan: plans.length ? String(i.plan) : "" });
  }
  const { error: rpcErr } = await db.rpc("place_order", { p_user: req.user.id, p_items: lines, p_total: total, p_note: String(req.body?.note || "").trim().slice(0, 300) || null });
  if (rpcErr) return res.status(400).json({ error: /insufficient/i.test(rpcErr.message) ? "Insufficient balance. Deposit funds first." : /out of stock/i.test(rpcErr.message) ? "Sorry, this item just sold out. Please try again or contact support." : "Could not place order." });
  res.status(201).json({ ok: true, total });
});
app.get("/api/orders", requireDb, authenticate, async (req, res) => {
  const { data, error } = await db.from("orders").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
  ok(res, error, { orders: data || [] }, "Could not load orders.");
});

/* ---------- Admin: deposits & orders ---------- */
app.get("/api/admin/deposits", admin, async (req, res) => {
  const size = 50;
  const { from, to } = pageOf(req, size);
  let query = db.from("deposits").select("*").order("created_at", { ascending: false }).range(from, to + 1);
  if (req.query.status) query = query.eq("status", String(req.query.status));
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: "Could not load deposits." });
  const list = (data || []).slice(0, size);

  /* attach the customer's name and whether a receipt screenshot was uploaded */
  const userIds = [...new Set(list.map((d) => d.user_id).filter(Boolean))];
  const people = {};
  if (userIds.length) {
    const { data: ps } = await db.from("profiles").select("id,email,first_name,last_name,phone").in("id", userIds);
    (ps || []).forEach((p) => { people[p.id] = p; });
  }
  const withReceipt = new Set();
  if (list.length) {
    const { data: rs } = await db.from("deposit_receipts").select("deposit_id").in("deposit_id", list.map((d) => String(d.id)));
    (rs || []).forEach((r) => withReceipt.add(String(r.deposit_id)));
  }
  res.json({
    deposits: list.map((d) => ({ ...d, profiles: people[d.user_id] || null, has_receipt: withReceipt.has(String(d.id)) })),
    more: (data || []).length > size
  });
});
app.get("/api/admin/deposits/:id/receipt", admin, async (req, res) => {
  const { data, error } = await db.from("deposit_receipts").select("image").eq("deposit_id", String(req.params.id)).maybeSingle();
  if (error) return res.status(500).json({ error: "Could not load the receipt." });
  if (!data) return res.status(404).json({ error: "No receipt was uploaded for this deposit." });
  res.json({ receipt: data.image });
});
app.post("/api/admin/deposits/:id/approve", admin, async (req, res) => {
  const { error } = await db.rpc("approve_deposit", { p_id: req.params.id });
  ok(res, error, { approved: true }, "Could not approve (already handled?).");
});
app.post("/api/admin/deposits/:id/reject", admin, async (req, res) => {
  const { error } = await db.from("deposits").update({ status: "rejected" }).eq("id", req.params.id).eq("status", "pending");
  ok(res, error, { rejected: true }, "Could not reject.");
});
app.get("/api/admin/orders", admin, async (req, res) => {
  const size = 50;
  const { from, to } = pageOf(req, size);
  let query = db.from("orders").select("*, profiles(email,first_name,last_name,phone)").order("created_at", { ascending: false }).range(from, to + 1);
  if (req.query.status) query = query.eq("status", String(req.query.status));
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: "Could not load orders." });
  res.json({ orders: (data || []).slice(0, size), more: (data || []).length > size });
});
app.get("/api/admin/customers", admin, async (req, res) => {
  const size = 50;
  const { from, to } = pageOf(req, size);
  let query = db.from("profiles").select("id,email,first_name,last_name,phone,balance,created_at", { count: "exact" }).order("created_at", { ascending: false }).range(from, to);
  const q = san(req.query.q);
  if (q) query = query.or("email.ilike.%" + q + "%,first_name.ilike.%" + q + "%,last_name.ilike.%" + q + "%,phone.ilike.%" + q + "%");
  const { data, error, count } = await query;
  if (error) return res.status(500).json({ error: "Could not load customers." });
  res.json({ customers: data || [], total: count || 0, more: from + (data || []).length < (count || 0) });
});
app.put("/api/admin/orders/:id/deliver", admin, async (req, res) => {
  const delivery = String(req.body?.delivery || "").trim().slice(0, 2000);
  const { error } = await db.from("orders").update({ status: "delivered", delivery: delivery || null, delivered_at: new Date().toISOString() }).eq("id", req.params.id);
  ok(res, error, { delivered: true }, "Could not update order.");
});

/* ---------- Flutterwave online payments (wallet funding) ---------- */
const FLW_BASE = "https://api.flutterwave.com/v3";
const flwKey = process.env.FLW_SECRET_KEY;
async function flw(path, options = {}) {
  const r = await fetch(FLW_BASE + path, {
    ...options,
    headers: { Authorization: "Bearer " + flwKey, "Content-Type": "application/json" }
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, j };
}
async function creditByRef(txRef) {
  const v = await flw("/transactions/verify_by_reference?tx_ref=" + encodeURIComponent(txRef));
  const t = v.j?.data;
  if (!v.ok || !t) return { credited: false, status: "not found" };
  if (t.status !== "successful" || t.currency !== "NGN") return { credited: false, status: String(t.status || "unknown") };
  const { data: dep } = await db.from("deposits").select("*").eq("reference", txRef).maybeSingle();
  if (!dep) return { credited: false, status: "unknown reference" };
  if (Number(t.amount) < Number(dep.amount)) return { credited: false, status: "amount mismatch" };
  if (dep.status !== "pending") return { credited: false, status: dep.status };
  const { error } = await db.rpc("approve_deposit", { p_id: dep.id });
  return { credited: !error, status: error ? "pending" : "successful" };
}
app.get("/api/payments/config", (_req, res) => res.json({ online: Boolean(flwKey) }));
app.post("/api/payments/start", requireDb, authenticate, async (req, res) => {
  if (!flwKey) return res.status(503).json({ error: "Online payment is not available yet. Please use bank transfer." });
  const amount = Math.round(Number(req.body?.amount));
  if (!(amount >= 100) || amount > 2000000) return res.status(400).json({ error: "Enter an amount from ₦100 to ₦2,000,000." });
  if (limited("pay:" + req.user.id, 10)) return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  const txRef = "dbm-" + String(req.user.id).slice(0, 8) + "-" + Date.now();
  const { error: depError } = await db.from("deposits").insert({ user_id: req.user.id, amount, reference: txRef, status: "pending" });
  if (depError) return res.status(500).json({ error: "Could not start the payment." });
  const redirect = process.env.PAYMENT_REDIRECT_URL || allowedOrigins[0] || "";
  const r = await flw("/payments", {
    method: "POST",
    body: JSON.stringify({
      tx_ref: txRef, amount, currency: "NGN", redirect_url: redirect,
      customer: { email: req.user.email },
      customizations: { title: "DeeBlaq's Market", description: "Wallet funding" }
    })
  });
  const link = r.j?.data?.link;
  if (!r.ok || !link) return res.status(502).json({ error: "Could not open the payment page. Please try again." });
  res.json({ link, tx_ref: txRef });
});
app.get("/api/payments/verify", requireDb, authenticate, async (req, res) => {
  const txRef = String(req.query?.tx_ref || "");
  const { data: dep } = await db.from("deposits").select("id,user_id").eq("reference", txRef).maybeSingle();
  if (!dep || dep.user_id !== req.user.id) return res.status(404).json({ error: "Payment not found." });
  res.json(await creditByRef(txRef));
});
app.post("/api/webhooks/flutterwave", requireDb, async (req, res) => {
  const hash = process.env.FLW_SECRET_HASH;
  if (!hash || req.get("verif-hash") !== hash) return res.status(401).end();
  const txRef = req.body?.data?.tx_ref || req.body?.txRef;
  if (txRef) { try { await creditByRef(String(txRef)); } catch (e) { console.error("webhook error"); } }
  res.status(200).end();
});

/* ---------- Customer feedback (public read, admin write) ---------- */
app.get("/api/reviews", requireDb, async (_req, res) => {
  const { data, error } = await db.from("reviews").select("id,name,message,rating,created_at").order("created_at", { ascending: false }).limit(30);
  ok(res, error, { reviews: data || [] }, "Could not load feedback.");
});
app.post("/api/admin/reviews", admin, async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 60);
  const message = String(req.body?.message || "").trim().slice(0, 300);
  const rating = Math.max(1, Math.min(5, parseInt(req.body?.rating, 10) || 5));
  if (!name || !message) return res.status(400).json({ error: "Name and message are required." });
  const { data, error } = await db.from("reviews").insert({ name, message, rating }).select().single();
  ok(res, error, { review: data }, "Could not save feedback.");
});
app.delete("/api/admin/reviews/:id", admin, async (req, res) => {
  const { error } = await db.from("reviews").delete().eq("id", req.params.id);
  ok(res, error, { deleted: true }, "Could not delete feedback.");
});

/* ---------- Admin: stock for automatic delivery ---------- */
app.get("/api/admin/stock", admin, async (_req, res) => {
  const { data, error } = await db.from("stock_summary").select("product_id,plan,name,total,available").order("available", { ascending: true }).limit(100);
  if (error) return res.status(500).json({ error: "Could not load stock." });
  res.json({ stock: data || [] });
});
app.post("/api/admin/stock", admin, async (req, res) => {
  const product_id = String(req.body?.product_id || "").trim();
  const plan = String(req.body?.plan || "").trim().slice(0, 40);
  const raw = Array.isArray(req.body?.lines) ? req.body.lines : String(req.body?.lines || "").split("\n");
  const lines = raw.map((l) => String(l).trim().slice(0, 500)).filter(Boolean).slice(0, 500);
  if (!product_id || !lines.length) return res.status(400).json({ error: "Choose a product and add at least one line." });
  const { error } = await db.from("stock").insert(lines.map((details) => ({ product_id, plan, details })));
  ok(res, error, { added: lines.length }, "Could not add stock.");
});

app.use((err, _req, res, _next) => {
  console.error(err?.message || "Unexpected server error");
  res.status(500).json({ error: "Unexpected server error." });
});

/* Vercel runs the app itself, so only start a server when running elsewhere (Render, your computer) */
if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`DeeBlaq's Market API listening on port ${port}`);
  });
}

module.exports = app;
