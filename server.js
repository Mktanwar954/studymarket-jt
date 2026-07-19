/**
 * StudyMarket — Full Backend (single-file build)
 * ------------------------------------------------
 * Everything (auth, products, cart, orders, payments, wallet, admin)
 * lives in this one file so it's easy to upload to GitHub from mobile
 * without folder-structure issues. Functionally identical to the
 * multi-file version.
 *
 * Setup:
 *   1. npm install
 *   2. Copy .env.example to .env and fill in your real values
 *   3. npm run migrate   (creates database tables from schema.sql)
 *   4. npm start
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const Razorpay = require("razorpay");
const slugify = require("slugify");

const app = express();
const SALT_ROUNDS = 12;
const COMMISSION_PERCENT = Number(process.env.PLATFORM_COMMISSION_PERCENT) || 10;
const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";

/* ============================================================
   DATABASE
   ============================================================ */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
  max: 20,
});
pool.on("error", (err) => console.error("Unexpected PG pool error:", err));

async function query(text, params) {
  return pool.query(text, params);
}

async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/* ============================================================
   ERROR HANDLING
   ============================================================ */
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function notFound(req, res) {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
}

function errorHandler(err, req, res, next) {
  console.error("Error:", err);
  if (err.code === "23505") return res.status(409).json({ error: "A record with this value already exists." });
  if (err.code === "23503") return res.status(400).json({ error: "Referenced record does not exist." });
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "File too large." });
  const status = err.status || 500;
  const message = status === 500 && process.env.NODE_ENV === "production" ? "Internal server error." : err.message;
  res.status(status).json({ error: message });
}

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ error: "Validation failed.", details: errors.array() });
  next();
}

/* ============================================================
   JWT HELPERS
   ============================================================ */
function signAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: process.env.JWT_ACCESS_EXPIRES || "15m" });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES || "30d" });
}
function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}
function verifyRefreshToken(token) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Authentication required." });

    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token." });
    }

    const result = await query("SELECT id, name, email, role, status FROM users WHERE id = $1", [decoded.sub]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "User no longer exists." });
    if (user.status === "banned") return res.status(403).json({ error: "Account banned." });
    if (user.status === "suspended") return res.status(403).json({ error: "Account suspended. Contact support." });

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Authentication required." });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "You do not have permission to perform this action." });
    next();
  };
}

/* ============================================================
   RATE LIMITERS
   ============================================================ */
const generalLimiter = rateLimit({
  windowMs: (Number(process.env.RATE_LIMIT_WINDOW_MIN) || 15) * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again in 15 minutes." },
});

/* ============================================================
   FILE UPLOAD (Multer)
   ============================================================ */
["covers", "previews", "originals"].forEach((d) => {
  const p = path.join(UPLOAD_DIR, d);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
});

function secureFilename(originalname) {
  const ext = path.extname(originalname);
  return `${crypto.randomBytes(24).toString("hex")}${ext}`;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === "cover_image") cb(null, path.join(UPLOAD_DIR, "covers"));
    else if (file.fieldname === "preview_file") cb(null, path.join(UPLOAD_DIR, "previews"));
    else if (file.fieldname === "original_file") cb(null, path.join(UPLOAD_DIR, "originals"));
    else cb(new Error("Unexpected field"), null);
  },
  filename: (req, file, cb) => cb(null, secureFilename(file.originalname)),
});

function fileFilter(req, file, cb) {
  const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"];
  const ALLOWED_DOC_TYPES = ["application/pdf"];
  if (file.fieldname === "cover_image" && !ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
    return cb(new Error("Cover image must be JPEG, PNG or WEBP."));
  }
  if ((file.fieldname === "preview_file" || file.fieldname === "original_file") && !ALLOWED_DOC_TYPES.includes(file.mimetype)) {
    return cb(new Error("Preview and original files must be PDF."));
  }
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: (Number(process.env.MAX_FILE_SIZE_MB) || 50) * 1024 * 1024 },
});

function generateDownloadToken({ productId, buyerId, fileKey, type }) {
  return jwt.sign({ productId, buyerId, fileKey, type }, process.env.JWT_ACCESS_SECRET, { expiresIn: "10m" });
}
function verifyDownloadToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}
function resolveFilePath(fileKey, type) {
  const subdir = type === "cover" ? "covers" : type === "preview" ? "previews" : "originals";
  const resolved = path.join(UPLOAD_DIR, subdir, fileKey);
  const baseDir = path.resolve(UPLOAD_DIR, subdir);
  if (!path.resolve(resolved).startsWith(baseDir)) throw new Error("Invalid file path.");
  if (!fs.existsSync(resolved)) throw new Error("File not found.");
  return resolved;
}

/* ============================================================
   RAZORPAY
   ============================================================ */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

async function createRazorpayOrder({ amount, receipt, notes }) {
  return razorpay.orders.create({ amount: Math.round(amount * 100), currency: "INR", receipt, notes });
}
function verifyPaymentSignature({ razorpay_order_id, razorpay_payment_id, razorpay_signature }) {
  const body_ = `${razorpay_order_id}|${razorpay_payment_id}`;
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(body_).digest("hex");
  return expected === razorpay_signature;
}
function verifyWebhookSignature(rawBody, signature) {
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET).update(rawBody).digest("hex");
  return expected === signature;
}

/* ============================================================
   WALLET / COMMISSION
   ============================================================ */
function calculateSplit(price) {
  const commission_amount = Math.round(price * (COMMISSION_PERCENT / 100) * 100) / 100;
  const seller_earning = Math.round((price - commission_amount) * 100) / 100;
  return { commission_rate: COMMISSION_PERCENT, commission_amount, seller_earning };
}

async function creditSellerWallet(client, { sellerId, amount, orderItemId, description }) {
  const walletResult = await client.query("SELECT id FROM wallets WHERE seller_id = $1 FOR UPDATE", [sellerId]);
  let walletId = walletResult.rows[0]?.id;
  if (!walletId) {
    const created = await client.query("INSERT INTO wallets (seller_id) VALUES ($1) RETURNING id", [sellerId]);
    walletId = created.rows[0].id;
  }
  await client.query(
    `UPDATE wallets SET pending_balance = pending_balance + $1, total_earned = total_earned + $1, updated_at = now() WHERE id = $2`,
    [amount, walletId]
  );
  await client.query(
    `INSERT INTO wallet_transactions (wallet_id, type, amount, reference_id, description) VALUES ($1, 'sale', $2, $3, $4)`,
    [walletId, amount, orderItemId, description]
  );
  return walletId;
}

/* ============================================================
   MIDDLEWARE SETUP
   ============================================================ */
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "*", credentials: true }));
app.use(compression());
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));
app.use(generalLimiter);

// Razorpay webhook needs raw body — must be registered BEFORE express.json()
app.post("/api/orders/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const signature = req.headers["x-razorpay-signature"];
    const rawBody = req.body.toString("utf8");
    if (!verifyWebhookSignature(rawBody, signature)) {
      return res.status(400).json({ error: "Invalid webhook signature." });
    }
    const payload = JSON.parse(rawBody);
    if (payload.event === "payment.captured") {
      const payment = payload.payload.payment.entity;
      await markOrderPaid({ razorpayOrderId: payment.order_id, razorpayPaymentId: payment.id, razorpaySignature: "webhook-verified" });
    }
    res.status(200).json({ received: true });
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(200).json({ received: true, note: "Processed with errors, logged for review." });
  }
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

/* ============================================================
   AUTH ROUTES
   ============================================================ */
function sanitizeUser(user) {
  const { password_hash, refresh_token_hash, reset_token, email_verify_token, ...safe } = user;
  return safe;
}

async function issueTokens(user) {
  const accessToken = signAccessToken({ sub: user.id, role: user.role });
  const refreshToken = signRefreshToken({ sub: user.id });
  await query("UPDATE users SET refresh_token_hash = $1 WHERE id = $2", [hashToken(refreshToken), user.id]);
  return { accessToken, refreshToken };
}

app.post(
  "/api/auth/register",
  authLimiter,
  [
    body("name").trim().isLength({ min: 2, max: 150 }),
    body("email").isEmail().normalizeEmail(),
    body("password").isLength({ min: 8 }).matches(/\d/),
    body("role").optional().isIn(["buyer", "seller"]),
  ],
  validate,
  async (req, res, next) => {
    try {
      const { name, email, password, role } = req.body;
      const chosenRole = ["buyer", "seller"].includes(role) ? role : "buyer";
      const existing = await query("SELECT id FROM users WHERE email = $1", [email.toLowerCase()]);
      if (existing.rows.length > 0) throw new ApiError(409, "An account with this email already exists.");

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      const result = await withTransaction(async (client) => {
        const userResult = await client.query(
          `INSERT INTO users (name, email, password_hash, role) VALUES ($1,$2,$3,$4)
           RETURNING id, name, email, role, status, created_at`,
          [name, email.toLowerCase(), passwordHash, chosenRole]
        );
        const user = userResult.rows[0];
        if (chosenRole === "seller") {
          const slug = `${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${user.id.slice(0, 6)}`;
          await client.query(`INSERT INTO seller_profiles (user_id, store_name, store_slug) VALUES ($1, $2, $3)`, [user.id, `${name}'s Store`, slug]);
          await client.query(`INSERT INTO wallets (seller_id) VALUES ($1)`, [user.id]);
        }
        return user;
      });

      const tokens = await issueTokens(result);
      res.status(201).json({ user: sanitizeUser(result), ...tokens });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/api/auth/login",
  authLimiter,
  [body("email").isEmail().normalizeEmail(), body("password").notEmpty()],
  validate,
  async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const result = await query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
      const user = result.rows[0];
      if (!user) throw new ApiError(401, "Invalid email or password.");
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) throw new ApiError(401, "Invalid email or password.");
      if (user.status === "banned") throw new ApiError(403, "This account has been banned.");
      if (user.status === "suspended") throw new ApiError(403, "This account is suspended. Contact support.");
      const tokens = await issueTokens(user);
      res.json({ user: sanitizeUser(user), ...tokens });
    } catch (err) {
      next(err);
    }
  }
);

app.post("/api/auth/refresh", [body("refreshToken").notEmpty()], validate, async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch {
      throw new ApiError(401, "Invalid or expired refresh token.");
    }
    const result = await query("SELECT * FROM users WHERE id = $1", [decoded.sub]);
    const user = result.rows[0];
    if (!user || user.refresh_token_hash !== hashToken(refreshToken)) {
      throw new ApiError(401, "Refresh token no longer valid. Please log in again.");
    }
    const tokens = await issueTokens(user);
    res.json({ user: sanitizeUser(user), ...tokens });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/logout", requireAuth, async (req, res, next) => {
  try {
    await query("UPDATE users SET refresh_token_hash = NULL WHERE id = $1", [req.user.id]);
    res.json({ message: "Logged out successfully." });
  } catch (err) {
    next(err);
  }
});

app.get("/api/auth/me", requireAuth, async (req, res, next) => {
  try {
    const result = await query("SELECT id, name, email, role, status, phone, avatar_url, created_at FROM users WHERE id = $1", [req.user.id]);
    res.json({ user: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   CATEGORY ROUTES
   ============================================================ */
app.get("/api/categories", async (req, res, next) => {
  try {
    const result = await query("SELECT id, name, slug, description FROM categories WHERE is_active = TRUE ORDER BY name ASC");
    res.json({ categories: result.rows });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   PRODUCT ROUTES
   ============================================================ */
app.get("/api/products", async (req, res, next) => {
  try {
    const { q, category, subject, course, university, semester, minPrice, maxPrice, sort = "newest", page = 1, limit = 20 } = req.query;
    const conditions = ["p.status = 'approved'", "p.is_active = TRUE"];
    const params = [];
    let idx = 1;

    if (q) { conditions.push(`to_tsvector('english', p.title || ' ' || coalesce(p.subject,'') || ' ' || coalesce(p.course,'') || ' ' || coalesce(p.university,'')) @@ plainto_tsquery('english', $${idx})`); params.push(q); idx++; }
    if (category) { conditions.push(`c.slug = $${idx}`); params.push(category); idx++; }
    if (subject) { conditions.push(`p.subject ILIKE $${idx}`); params.push(`%${subject}%`); idx++; }
    if (course) { conditions.push(`p.course ILIKE $${idx}`); params.push(`%${course}%`); idx++; }
    if (university) { conditions.push(`p.university ILIKE $${idx}`); params.push(`%${university}%`); idx++; }
    if (semester) { conditions.push(`p.semester = $${idx}`); params.push(semester); idx++; }
    if (minPrice) { conditions.push(`p.price >= $${idx}`); params.push(minPrice); idx++; }
    if (maxPrice) { conditions.push(`p.price <= $${idx}`); params.push(maxPrice); idx++; }

    const sortMap = { newest: "p.created_at DESC", popular: "p.sales_count DESC", price_low: "p.price ASC", price_high: "p.price DESC", rating: "p.rating_avg DESC" };
    const orderBy = sortMap[sort] || sortMap.newest;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;
    const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const countResult = await query(`SELECT COUNT(*)::int AS total FROM products p JOIN categories c ON p.category_id = c.id ${whereClause}`, params);
    params.push(limitNum, offset);
    const result = await query(
      `SELECT p.id, p.title, p.slug, p.subject, p.course, p.university, p.semester, p.price, p.mrp, p.product_type,
              p.rating_avg, p.rating_count, p.sales_count, p.cover_image_key, c.name AS category_name, c.slug AS category_slug,
              u.id AS seller_id, sp.store_name, sp.verified AS seller_verified
       FROM products p JOIN categories c ON p.category_id = c.id JOIN users u ON p.seller_id = u.id JOIN seller_profiles sp ON sp.user_id = u.id
       ${whereClause} ORDER BY ${orderBy} LIMIT $${idx} OFFSET $${idx + 1}`,
      params
    );

    res.json({ products: result.rows, pagination: { page: pageNum, limit: limitNum, total: countResult.rows[0].total, totalPages: Math.ceil(countResult.rows[0].total / limitNum) } });
  } catch (err) {
    next(err);
  }
});

app.get("/api/products/seller/mine", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, title, slug, price, status, sales_count, rating_avg, created_at, cover_image_key FROM products WHERE seller_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ products: result.rows });
  } catch (err) {
    next(err);
  }
});

app.get("/api/products/:id/analytics", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const { id } = req.params;
    const product = await query("SELECT seller_id, sales_count, view_count, rating_avg FROM products WHERE id = $1", [id]);
    if (!product.rows[0]) throw new ApiError(404, "Product not found.");
    if (product.rows[0].seller_id !== req.user.id) throw new ApiError(403, "Not your product.");
    const salesOverTime = await query(
      `SELECT DATE_TRUNC('day', oi.created_at) AS day, COUNT(*)::int AS sales, SUM(oi.seller_earning) AS earnings
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.product_id = $1 AND o.status = 'paid' GROUP BY day ORDER BY day DESC LIMIT 30`,
      [id]
    );
    res.json({ summary: product.rows[0], salesOverTime: salesOverTime.rows });
  } catch (err) {
    next(err);
  }
});

app.get("/api/products/:slug", async (req, res, next) => {
  try {
    const { slug } = req.params;
    const result = await query(
      `SELECT p.*, c.name AS category_name, c.slug AS category_slug, u.id AS seller_id, u.name AS seller_name,
              sp.store_name, sp.store_slug, sp.verified AS seller_verified, sp.rating_avg AS seller_rating, sp.total_sales AS seller_total_sales
       FROM products p JOIN categories c ON p.category_id = c.id JOIN users u ON p.seller_id = u.id JOIN seller_profiles sp ON sp.user_id = u.id
       WHERE p.slug = $1 AND p.status = 'approved' AND p.is_active = TRUE`,
      [slug]
    );
    const product = result.rows[0];
    if (!product) throw new ApiError(404, "Product not found.");
    query("UPDATE products SET view_count = view_count + 1 WHERE id = $1", [product.id]).catch(() => {});
    delete product.original_file_key;

    const related = await query(
      `SELECT id, title, slug, price, mrp, cover_image_key, rating_avg FROM products WHERE category_id = $1 AND id != $2 AND status = 'approved' AND is_active = TRUE ORDER BY sales_count DESC LIMIT 4`,
      [product.category_id, product.id]
    );
    const reviews = await query(
      `SELECT r.rating, r.comment, r.created_at, u.name AS buyer_name FROM reviews r JOIN users u ON r.buyer_id = u.id WHERE r.product_id = $1 ORDER BY r.created_at DESC LIMIT 10`,
      [product.id]
    );
    res.json({ product, related: related.rows, reviews: reviews.rows });
  } catch (err) {
    next(err);
  }
});

app.post(
  "/api/products",
  requireAuth,
  requireRole("seller"),
  upload.fields([{ name: "cover_image", maxCount: 1 }, { name: "preview_file", maxCount: 1 }, { name: "original_file", maxCount: 1 }]),
  [body("title").trim().isLength({ min: 5, max: 255 }), body("description").trim().isLength({ min: 20 }), body("category_id").isUUID(), body("product_type").notEmpty(), body("price").isFloat({ min: 0 })],
  validate,
  async (req, res, next) => {
    try {
      const { title, description, category_id, subject, course, university, semester, language, product_type, price, mrp } = req.body;
      if (!req.files || !req.files.original_file) throw new ApiError(400, "Original file (PDF) is required.");

      const baseSlug = slugify(title, { lower: true, strict: true });
      const uniqueSlug = `${baseSlug}-${Date.now().toString(36)}`;
      const originalFile = req.files.original_file[0];
      const previewFile = req.files.preview_file ? req.files.preview_file[0] : null;
      const coverFile = req.files.cover_image ? req.files.cover_image[0] : null;

      const result = await query(
        `INSERT INTO products (seller_id, category_id, title, slug, description, subject, course, university, semester, language, product_type, price, mrp, cover_image_key, preview_file_key, original_file_key, file_size_bytes, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'pending') RETURNING id, title, slug, status, created_at`,
        [req.user.id, category_id, title, uniqueSlug, description, subject, course, university, semester, language || "English", product_type, price, mrp || null,
         coverFile ? coverFile.filename : null, previewFile ? previewFile.filename : null, originalFile.filename, originalFile.size]
      );
      res.status(201).json({ product: result.rows[0], message: "Product submitted for review." });
    } catch (err) {
      next(err);
    }
  }
);

app.put("/api/products/:id", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const { id } = req.params;
    const existing = await query("SELECT * FROM products WHERE id = $1", [id]);
    const product = existing.rows[0];
    if (!product) throw new ApiError(404, "Product not found.");
    if (product.seller_id !== req.user.id) throw new ApiError(403, "Not your product.");

    const fields = ["title", "description", "subject", "course", "university", "semester", "language", "price", "mrp", "product_type"];
    const updates = [];
    const params = [];
    let idx = 1;
    fields.forEach((f) => { if (req.body[f] !== undefined) { updates.push(`${f} = $${idx}`); params.push(req.body[f]); idx++; } });
    if (updates.length === 0) throw new ApiError(400, "No valid fields to update.");
    updates.push(`status = 'pending'`);
    params.push(id);
    const result = await query(`UPDATE products SET ${updates.join(", ")} WHERE id = $${idx} RETURNING id, title, status`, params);
    res.json({ product: result.rows[0], message: "Product updated and re-submitted for review." });
  } catch (err) {
    next(err);
  }
});

app.delete("/api/products/:id", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const { id } = req.params;
    const existing = await query("SELECT seller_id FROM products WHERE id = $1", [id]);
    if (!existing.rows[0]) throw new ApiError(404, "Product not found.");
    if (existing.rows[0].seller_id !== req.user.id) throw new ApiError(403, "Not your product.");
    await query("UPDATE products SET is_active = FALSE WHERE id = $1", [id]);
    res.json({ message: "Product removed." });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   CART ROUTES
   ============================================================ */
app.get("/api/cart", requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT ci.id AS cart_item_id, p.id AS product_id, p.title, p.price, p.cover_image_key, p.slug, sp.store_name
       FROM cart_items ci JOIN products p ON ci.product_id = p.id JOIN seller_profiles sp ON sp.user_id = p.seller_id
       WHERE ci.user_id = $1 AND p.is_active = TRUE AND p.status = 'approved' ORDER BY ci.created_at DESC`,
      [req.user.id]
    );
    const total = result.rows.reduce((sum, item) => sum + Number(item.price), 0);
    res.json({ items: result.rows, total });
  } catch (err) {
    next(err);
  }
});

app.post("/api/cart", requireAuth, async (req, res, next) => {
  try {
    const { product_id } = req.body;
    if (!product_id) throw new ApiError(400, "product_id is required.");
    const product = await query("SELECT id, seller_id FROM products WHERE id = $1 AND status = 'approved' AND is_active = TRUE", [product_id]);
    if (!product.rows[0]) throw new ApiError(404, "Product not found.");
    if (product.rows[0].seller_id === req.user.id) throw new ApiError(400, "You cannot buy your own product.");
    const owned = await query("SELECT id FROM entitlements WHERE buyer_id = $1 AND product_id = $2", [req.user.id, product_id]);
    if (owned.rows[0]) throw new ApiError(409, "You already own this product.");
    await query(`INSERT INTO cart_items (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING`, [req.user.id, product_id]);
    res.status(201).json({ message: "Added to cart." });
  } catch (err) {
    next(err);
  }
});

app.delete("/api/cart/:productId", requireAuth, async (req, res, next) => {
  try {
    await query("DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2", [req.user.id, req.params.productId]);
    res.json({ message: "Removed from cart." });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   WISHLIST ROUTES
   ============================================================ */
app.get("/api/wishlist", requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT p.id AS product_id, p.title, p.price, p.mrp, p.cover_image_key, p.slug, p.rating_avg
       FROM wishlist_items w JOIN products p ON w.product_id = p.id WHERE w.user_id = $1 AND p.is_active = TRUE ORDER BY w.created_at DESC`,
      [req.user.id]
    );
    res.json({ items: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/wishlist", requireAuth, async (req, res, next) => {
  try {
    const { product_id } = req.body;
    if (!product_id) throw new ApiError(400, "product_id is required.");
    await query(`INSERT INTO wishlist_items (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING`, [req.user.id, product_id]);
    res.status(201).json({ message: "Added to wishlist." });
  } catch (err) {
    next(err);
  }
});

app.delete("/api/wishlist/:productId", requireAuth, async (req, res, next) => {
  try {
    await query("DELETE FROM wishlist_items WHERE user_id = $1 AND product_id = $2", [req.user.id, req.params.productId]);
    res.json({ message: "Removed from wishlist." });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   ORDER / CHECKOUT ROUTES
   ============================================================ */
function generateOrderNumber() {
  return `SM${Date.now()}${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
}

app.post("/api/orders/checkout", requireAuth, async (req, res, next) => {
  try {
    const { product_ids } = req.body;
    if (!Array.isArray(product_ids) || product_ids.length === 0) throw new ApiError(400, "product_ids array is required.");

    const products = await query(`SELECT id, seller_id, price, title FROM products WHERE id = ANY($1::uuid[]) AND status = 'approved' AND is_active = TRUE`, [product_ids]);
    if (products.rows.length !== product_ids.length) throw new ApiError(400, "One or more products are unavailable.");
    for (const p of products.rows) { if (p.seller_id === req.user.id) throw new ApiError(400, `You cannot buy your own product: ${p.title}`); }

    const alreadyOwned = await query(`SELECT product_id FROM entitlements WHERE buyer_id = $1 AND product_id = ANY($2::uuid[])`, [req.user.id, product_ids]);
    if (alreadyOwned.rows.length > 0) throw new ApiError(409, "You already own one or more of these products.");

    const subtotal = products.rows.reduce((sum, p) => sum + Number(p.price), 0);
    const orderNumber = generateOrderNumber();

    const localOrder = await withTransaction(async (client) => {
      const orderResult = await client.query(
        `INSERT INTO orders (buyer_id, order_number, subtotal, total_amount, status) VALUES ($1, $2, $3, $4, 'created') RETURNING id, order_number, total_amount`,
        [req.user.id, orderNumber, subtotal, subtotal]
      );
      const order = orderResult.rows[0];
      for (const p of products.rows) {
        const split = calculateSplit(Number(p.price));
        await client.query(
          `INSERT INTO order_items (order_id, product_id, seller_id, unit_price, commission_rate, commission_amount, seller_earning) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [order.id, p.id, p.seller_id, p.price, split.commission_rate, split.commission_amount, split.seller_earning]
        );
      }
      return order;
    });

    const razorpayOrder = await createRazorpayOrder({ amount: subtotal, receipt: localOrder.order_number, notes: { order_id: localOrder.id, buyer_id: req.user.id } });
    await query("UPDATE orders SET razorpay_order_id = $1 WHERE id = $2", [razorpayOrder.id, localOrder.id]);

    res.status(201).json({
      order_id: localOrder.id, order_number: localOrder.order_number, amount: subtotal,
      razorpay_order_id: razorpayOrder.id, razorpay_key_id: process.env.RAZORPAY_KEY_ID, currency: "INR",
    });
  } catch (err) {
    next(err);
  }
});

async function markOrderPaid({ razorpayOrderId, razorpayPaymentId, razorpaySignature }) {
  return withTransaction(async (client) => {
    const orderResult = await client.query("SELECT * FROM orders WHERE razorpay_order_id = $1 FOR UPDATE", [razorpayOrderId]);
    const order = orderResult.rows[0];
    if (!order) throw new ApiError(404, "Order not found for this payment.");
    if (order.status === "paid") return { id: order.id, status: "paid", already_processed: true };

    await client.query(`UPDATE orders SET status = 'paid', razorpay_payment_id = $1, razorpay_signature = $2, paid_at = now() WHERE id = $3`, [razorpayPaymentId, razorpaySignature, order.id]);
    const items = await client.query("SELECT * FROM order_items WHERE order_id = $1", [order.id]);

    for (const item of items.rows) {
      await client.query(`INSERT INTO entitlements (buyer_id, product_id, order_id) VALUES ($1, $2, $3) ON CONFLICT (buyer_id, product_id) DO NOTHING`, [order.buyer_id, item.product_id, order.id]);
      await creditSellerWallet(client, { sellerId: item.seller_id, amount: Number(item.seller_earning), orderItemId: item.id, description: `Sale of product ${item.product_id}` });
      await client.query("UPDATE products SET sales_count = sales_count + 1 WHERE id = $1", [item.product_id]);
      await client.query("UPDATE seller_profiles SET total_sales = total_sales + 1 WHERE user_id = $1", [item.seller_id]);
    }
    return { id: order.id, status: "paid" };
  });
}

app.post("/api/orders/verify", requireAuth, async (req, res, next) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) throw new ApiError(400, "Missing payment verification fields.");
    if (!verifyPaymentSignature({ razorpay_order_id, razorpay_payment_id, razorpay_signature })) throw new ApiError(400, "Payment verification failed. Signature mismatch.");
    const result = await markOrderPaid({ razorpayOrderId: razorpay_order_id, razorpayPaymentId: razorpay_payment_id, razorpaySignature: razorpay_signature });
    res.json({ message: "Payment verified successfully.", order: result });
  } catch (err) {
    next(err);
  }
});

app.get("/api/orders/my", requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT o.id, o.order_number, o.total_amount, o.status, o.paid_at, o.created_at,
              json_agg(json_build_object('product_id', p.id, 'title', p.title, 'slug', p.slug, 'price', oi.unit_price, 'cover_image_key', p.cover_image_key)) AS items
       FROM orders o JOIN order_items oi ON oi.order_id = o.id JOIN products p ON p.id = oi.product_id
       WHERE o.buyer_id = $1 GROUP BY o.id ORDER BY o.created_at DESC`,
      [req.user.id]
    );
    res.json({ orders: result.rows });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   DOWNLOAD ROUTES
   ============================================================ */
app.post("/api/downloads/request/:productId", requireAuth, async (req, res, next) => {
  try {
    const { productId } = req.params;
    const entitlement = await query("SELECT id, download_count FROM entitlements WHERE buyer_id = $1 AND product_id = $2", [req.user.id, productId]);
    if (!entitlement.rows[0]) throw new ApiError(403, "You have not purchased this product.");
    const product = await query("SELECT original_file_key FROM products WHERE id = $1", [productId]);
    if (!product.rows[0]) throw new ApiError(404, "Product not found.");
    const token = generateDownloadToken({ productId, buyerId: req.user.id, fileKey: product.rows[0].original_file_key, type: "original" });
    res.json({ download_url: `/api/downloads/file/${token}`, expires_in_seconds: 600 });
  } catch (err) {
    next(err);
  }
});

app.get("/api/downloads/file/:token", async (req, res, next) => {
  try {
    let decoded;
    try {
      decoded = verifyDownloadToken(req.params.token);
    } catch {
      throw new ApiError(401, "Download link expired or invalid. Please request a new one.");
    }
    const filePath = resolveFilePath(decoded.fileKey, decoded.type);
    query("UPDATE entitlements SET download_count = download_count + 1 WHERE buyer_id = $1 AND product_id = $2", [decoded.buyerId, decoded.productId]).catch(() => {});
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="studymarket-notes.pdf"`);
    res.setHeader("X-Content-Type-Options", "nosniff");
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    next(err);
  }
});

app.get("/api/downloads/preview/:productId", async (req, res, next) => {
  try {
    const product = await query("SELECT preview_file_key FROM products WHERE id = $1 AND status = 'approved'", [req.params.productId]);
    if (!product.rows[0] || !product.rows[0].preview_file_key) throw new ApiError(404, "Preview not available for this product.");
    const filePath = resolveFilePath(product.rows[0].preview_file_key, "preview");
    res.setHeader("Content-Type", "application/pdf");
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   WALLET ROUTES
   ============================================================ */
app.get("/api/wallet", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const result = await query("SELECT * FROM wallets WHERE seller_id = $1", [req.user.id]);
    let wallet = result.rows[0];
    if (!wallet) {
      const created = await query("INSERT INTO wallets (seller_id) VALUES ($1) RETURNING *", [req.user.id]);
      wallet = created.rows[0];
    }
    res.json({ wallet });
  } catch (err) {
    next(err);
  }
});

app.get("/api/wallet/transactions", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const wallet = await query("SELECT id FROM wallets WHERE seller_id = $1", [req.user.id]);
    if (!wallet.rows[0]) return res.json({ transactions: [] });
    const result = await query("SELECT id, type, amount, description, created_at FROM wallet_transactions WHERE wallet_id = $1 ORDER BY created_at DESC LIMIT 100", [wallet.rows[0].id]);
    res.json({ transactions: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/wallet/withdraw", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const amt = Number(req.body.amount);
    if (!amt || amt <= 0) throw new ApiError(400, "Enter a valid withdrawal amount.");

    const result = await withTransaction(async (client) => {
      const walletResult = await client.query("SELECT * FROM wallets WHERE seller_id = $1 FOR UPDATE", [req.user.id]);
      const wallet = walletResult.rows[0];
      if (!wallet) throw new ApiError(404, "Wallet not found.");
      if (amt > Number(wallet.available_balance)) throw new ApiError(400, "Withdrawal amount exceeds available balance.");

      const profile = await client.query("SELECT bank_account_no, upi_id FROM seller_profiles WHERE user_id = $1", [req.user.id]);
      if (!profile.rows[0]?.bank_account_no && !profile.rows[0]?.upi_id) throw new ApiError(400, "Please add your bank account or UPI details before withdrawing.");

      await client.query("UPDATE wallets SET available_balance = available_balance - $1 WHERE id = $2", [amt, wallet.id]);
      const withdrawal = await client.query(`INSERT INTO withdrawals (seller_id, wallet_id, amount, status) VALUES ($1, $2, $3, 'pending') RETURNING id, amount, status, created_at`, [req.user.id, wallet.id, amt]);
      await client.query(`INSERT INTO wallet_transactions (wallet_id, type, amount, reference_id, description) VALUES ($1, 'withdrawal', $2, $3, 'Withdrawal request submitted')`, [wallet.id, -amt, withdrawal.rows[0].id]);
      return withdrawal.rows[0];
    });

    res.status(201).json({ withdrawal: result, message: "Withdrawal request submitted." });
  } catch (err) {
    next(err);
  }
});

app.get("/api/wallet/withdrawals", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const result = await query("SELECT id, amount, status, admin_note, created_at, processed_at FROM withdrawals WHERE seller_id = $1 ORDER BY created_at DESC", [req.user.id]);
    res.json({ withdrawals: result.rows });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   REVIEW ROUTES
   ============================================================ */
app.post("/api/reviews", requireAuth, async (req, res, next) => {
  try {
    const { product_id, rating, comment } = req.body;
    const ratingNum = Number(rating);
    if (!product_id || !ratingNum || ratingNum < 1 || ratingNum > 5) throw new ApiError(400, "Valid product_id and rating (1-5) required.");

    const entitlement = await query("SELECT order_id FROM entitlements WHERE buyer_id = $1 AND product_id = $2", [req.user.id, product_id]);
    if (!entitlement.rows[0]) throw new ApiError(403, "You can only review products you have purchased.");

    const result = await withTransaction(async (client) => {
      const review = await client.query(
        `INSERT INTO reviews (product_id, buyer_id, order_id, rating, comment) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (product_id, buyer_id) DO UPDATE SET rating = $4, comment = $5 RETURNING id, rating, comment, created_at`,
        [product_id, req.user.id, entitlement.rows[0].order_id, ratingNum, comment || null]
      );
      const agg = await client.query("SELECT AVG(rating)::numeric(3,2) AS avg, COUNT(*)::int AS count FROM reviews WHERE product_id = $1", [product_id]);
      await client.query("UPDATE products SET rating_avg = $1, rating_count = $2 WHERE id = $3", [agg.rows[0].avg, agg.rows[0].count, product_id]);
      return review.rows[0];
    });

    res.status(201).json({ review: result });
  } catch (err) {
    next(err);
  }
});

app.get("/api/reviews/product/:productId", async (req, res, next) => {
  try {
    const result = await query("SELECT r.id, r.rating, r.comment, r.created_at, u.name AS buyer_name FROM reviews r JOIN users u ON r.buyer_id = u.id WHERE r.product_id = $1 ORDER BY r.created_at DESC", [req.params.productId]);
    res.json({ reviews: result.rows });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   SELLER PROFILE ROUTES
   ============================================================ */
app.get("/api/sellers/profile/me", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const result = await query("SELECT * FROM seller_profiles WHERE user_id = $1", [req.user.id]);
    if (!result.rows[0]) throw new ApiError(404, "Seller profile not found.");
    res.json({ profile: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.put("/api/sellers/profile", requireAuth, requireRole("seller"), async (req, res, next) => {
  try {
    const { store_name, bio, bank_account_no, bank_ifsc, bank_holder, upi_id } = req.body;
    const fields = [];
    const params = [];
    let idx = 1;
    const map = { store_name, bio, bank_account_no, bank_ifsc, bank_holder, upi_id };
    Object.entries(map).forEach(([key, value]) => { if (value !== undefined) { fields.push(`${key} = $${idx}`); params.push(value); idx++; } });
    if (fields.length === 0) throw new ApiError(400, "No fields to update.");
    params.push(req.user.id);
    const result = await query(`UPDATE seller_profiles SET ${fields.join(", ")} WHERE user_id = $${idx} RETURNING *`, params);
    if (!result.rows[0]) throw new ApiError(404, "Seller profile not found.");
    res.json({ profile: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.get("/api/sellers/:slug", async (req, res, next) => {
  try {
    const profile = await query(
      `SELECT sp.store_name, sp.store_slug, sp.bio, sp.verified, sp.rating_avg, sp.rating_count, sp.total_sales, u.name AS seller_name, u.created_at AS joined_at
       FROM seller_profiles sp JOIN users u ON sp.user_id = u.id WHERE sp.store_slug = $1`,
      [req.params.slug]
    );
    if (!profile.rows[0]) throw new ApiError(404, "Store not found.");
    const products = await query(
      `SELECT p.id, p.title, p.slug, p.price, p.mrp, p.cover_image_key, p.rating_avg FROM products p JOIN seller_profiles sp ON p.seller_id = sp.user_id
       WHERE sp.store_slug = $1 AND p.status = 'approved' AND p.is_active = TRUE ORDER BY p.created_at DESC`,
      [req.params.slug]
    );
    res.json({ store: profile.rows[0], products: products.rows });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   REPORT ROUTES
   ============================================================ */
app.post("/api/reports", requireAuth, async (req, res, next) => {
  try {
    const { product_id, reason } = req.body;
    if (!product_id || !reason) throw new ApiError(400, "product_id and reason are required.");
    const result = await query("INSERT INTO reports (reporter_id, product_id, reason) VALUES ($1,$2,$3) RETURNING id, created_at", [req.user.id, product_id, reason]);
    res.status(201).json({ report: result.rows[0], message: "Report submitted. Our team will review it." });
  } catch (err) {
    next(err);
  }
});

/* ============================================================
   ADMIN ROUTES
   ============================================================ */
async function logAdminAction(client, adminId, action, targetType, targetId, meta = {}) {
  await client.query(`INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, meta) VALUES ($1,$2,$3,$4,$5)`, [adminId, action, targetType, targetId, JSON.stringify(meta)]);
}

const adminRouter = express.Router();
adminRouter.use(requireAuth, requireRole("admin"));

adminRouter.get("/dashboard", async (req, res, next) => {
  try {
    const [users, sellers, products, revenue, pendingProducts, pendingWithdrawals] = await Promise.all([
      query("SELECT COUNT(*)::int AS count FROM users WHERE role != 'admin'"),
      query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'seller'"),
      query("SELECT COUNT(*)::int AS count FROM products WHERE status = 'approved'"),
      query(`SELECT COALESCE(SUM(commission_amount), 0) AS total FROM order_items oi JOIN orders o ON oi.order_id = o.id WHERE o.status = 'paid' AND o.paid_at >= date_trunc('month', now())`),
      query("SELECT COUNT(*)::int AS count FROM products WHERE status = 'pending'"),
      query("SELECT COUNT(*)::int AS count FROM withdrawals WHERE status = 'pending'"),
    ]);
    res.json({
      total_users: users.rows[0].count, total_sellers: sellers.rows[0].count, total_products: products.rows[0].count,
      monthly_platform_revenue: revenue.rows[0].total, pending_product_approvals: pendingProducts.rows[0].count, pending_withdrawals: pendingWithdrawals.rows[0].count,
    });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/products", async (req, res, next) => {
  try {
    const { status = "pending" } = req.query;
    const result = await query(
      `SELECT p.id, p.title, p.slug, p.price, p.status, p.created_at, u.name AS seller_name, u.email AS seller_email, c.name AS category_name
       FROM products p JOIN users u ON p.seller_id = u.id JOIN categories c ON p.category_id = c.id WHERE p.status = $1 ORDER BY p.created_at ASC`,
      [status]
    );
    res.json({ products: result.rows });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/products/:id/approve", async (req, res, next) => {
  try {
    const { id } = req.params;
    await withTransaction(async (client) => {
      const result = await client.query("UPDATE products SET status = 'approved', rejection_reason = NULL WHERE id = $1 RETURNING id", [id]);
      if (!result.rows[0]) throw new ApiError(404, "Product not found.");
      await logAdminAction(client, req.user.id, "approve_product", "product", id);
    });
    res.json({ message: "Product approved." });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/products/:id/reject", async (req, res, next) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    await withTransaction(async (client) => {
      const result = await client.query("UPDATE products SET status = 'rejected', rejection_reason = $1 WHERE id = $2 RETURNING id", [reason || "Did not meet quality guidelines.", id]);
      if (!result.rows[0]) throw new ApiError(404, "Product not found.");
      await logAdminAction(client, req.user.id, "reject_product", "product", id, { reason });
    });
    res.json({ message: "Product rejected." });
  } catch (err) {
    next(err);
  }
});

adminRouter.delete("/products/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    await withTransaction(async (client) => {
      const result = await client.query("UPDATE products SET status = 'removed', is_active = FALSE WHERE id = $1 RETURNING id", [id]);
      if (!result.rows[0]) throw new ApiError(404, "Product not found.");
      await logAdminAction(client, req.user.id, "remove_product", "product", id);
    });
    res.json({ message: "Product removed from marketplace." });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/users", async (req, res, next) => {
  try {
    const { role, status, q } = req.query;
    const conditions = [];
    const params = [];
    let idx = 1;
    if (role) { conditions.push(`role = $${idx}`); params.push(role); idx++; }
    if (status) { conditions.push(`status = $${idx}`); params.push(status); idx++; }
    if (q) { conditions.push(`(name ILIKE $${idx} OR email ILIKE $${idx})`); params.push(`%${q}%`); idx++; }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await query(`SELECT id, name, email, role, status, created_at FROM users ${where} ORDER BY created_at DESC LIMIT 200`, params);
    res.json({ users: result.rows });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/users/:id/suspend", async (req, res, next) => {
  try {
    const { id } = req.params;
    await withTransaction(async (client) => {
      const result = await client.query("UPDATE users SET status = 'suspended' WHERE id = $1 AND role != 'admin' RETURNING id", [id]);
      if (!result.rows[0]) throw new ApiError(404, "User not found or cannot be suspended.");
      await logAdminAction(client, req.user.id, "suspend_user", "user", id);
    });
    res.json({ message: "User suspended." });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/users/:id/reactivate", async (req, res, next) => {
  try {
    const { id } = req.params;
    await withTransaction(async (client) => {
      const result = await client.query("UPDATE users SET status = 'active' WHERE id = $1 RETURNING id", [id]);
      if (!result.rows[0]) throw new ApiError(404, "User not found.");
      await logAdminAction(client, req.user.id, "reactivate_user", "user", id);
    });
    res.json({ message: "User reactivated." });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/withdrawals", async (req, res, next) => {
  try {
    const { status = "pending" } = req.query;
    const result = await query(
      `SELECT w.id, w.amount, w.status, w.created_at, u.name AS seller_name, u.email AS seller_email, sp.bank_account_no, sp.bank_ifsc, sp.upi_id
       FROM withdrawals w JOIN users u ON w.seller_id = u.id JOIN seller_profiles sp ON sp.user_id = u.id WHERE w.status = $1 ORDER BY w.created_at ASC`,
      [status]
    );
    res.json({ withdrawals: result.rows });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/withdrawals/:id/approve", async (req, res, next) => {
  try {
    const { id } = req.params;
    await withTransaction(async (client) => {
      const withdrawal = await client.query("SELECT * FROM withdrawals WHERE id = $1 FOR UPDATE", [id]);
      if (!withdrawal.rows[0]) throw new ApiError(404, "Withdrawal not found.");
      if (withdrawal.rows[0].status !== "pending") throw new ApiError(400, "Withdrawal already processed.");
      await client.query("UPDATE withdrawals SET status = 'paid', processed_by = $1, processed_at = now() WHERE id = $2", [req.user.id, id]);
      await client.query("UPDATE wallets SET total_withdrawn = total_withdrawn + $1 WHERE id = $2", [withdrawal.rows[0].amount, withdrawal.rows[0].wallet_id]);
      await logAdminAction(client, req.user.id, "approve_withdrawal", "withdrawal", id);
    });
    res.json({ message: "Withdrawal marked as paid." });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/withdrawals/:id/reject", async (req, res, next) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    await withTransaction(async (client) => {
      const withdrawal = await client.query("SELECT * FROM withdrawals WHERE id = $1 FOR UPDATE", [id]);
      if (!withdrawal.rows[0]) throw new ApiError(404, "Withdrawal not found.");
      if (withdrawal.rows[0].status !== "pending") throw new ApiError(400, "Withdrawal already processed.");
      await client.query("UPDATE wallets SET available_balance = available_balance + $1 WHERE id = $2", [withdrawal.rows[0].amount, withdrawal.rows[0].wallet_id]);
      await client.query("UPDATE withdrawals SET status = 'rejected', admin_note = $1, processed_by = $2, processed_at = now() WHERE id = $3", [reason || "Rejected by admin.", req.user.id, id]);
      await logAdminAction(client, req.user.id, "reject_withdrawal", "withdrawal", id, { reason });
    });
    res.json({ message: "Withdrawal rejected and funds returned to seller wallet." });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/reports", async (req, res, next) => {
  try {
    const result = await query(
      `SELECT r.id, r.reason, r.status, r.created_at, p.title AS product_title, p.id AS product_id, u.name AS reporter_name
       FROM reports r LEFT JOIN products p ON r.product_id = p.id LEFT JOIN users u ON r.reporter_id = u.id ORDER BY r.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    next(err);
  }
});

app.use("/api/admin", adminRouter);
// ============ GEMINI AI ROUTES ============
const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// 1. CHAT
app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message, history } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
    const chat = model.startChat({
      history: [
        { role: 'user', parts: [{ text: 'You are StudyMarket-JT AI assistant. Help students with notes, studies, career. Reply in same language as user (Hindi/English/Hinglish).' }] },
        { role: 'model', parts: [{ text: 'Ready to help!' }] },
        ...(history || [])
      ]
    });
    const result = await chat.sendMessage(message);
    res.json({ reply: result.response.text() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. IMAGE GENERATION
app.post('/api/ai/image', async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt required' });
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-preview-image-generation' });
    const result = await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
    });
    const imagePart = result.response.candidates[0].content.parts.find(p => p.inlineData);
    if (imagePart) res.json({ image: imagePart.inlineData.data, mimeType: imagePart.inlineData.mimeType });
    else res.status(500).json({ error: 'Image generation failed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. PDF SUMMARY
app.post('/api/ai/pdf-summary', async (req, res) => {
  try {
    const { text, filename } = req.body;
    if (!text) return res.status(400).json({ error: 'Text required' });
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
    const result = await model.generateContent(`Summarize this document "${filename}":\n${text}\n\nFormat: Key Topics, Main Points, Important Definitions, Quick Revision Notes`);
    res.json({ summary: result.response.text() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
/* ============================================================
   ERROR HANDLERS (must be last)
   ============================================================ */
app.use(notFound);
app.use(errorHandler);

/* ============================================================
   START SERVER
   ============================================================ */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ StudyMarket API running on port ${PORT} [${process.env.NODE_ENV || "development"}]`);
});

module.exports = app;
