-- ============================================================
-- StudyMarket — PostgreSQL Database Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------
-- ENUM TYPES
-- ------------------------------------------------------------
CREATE TYPE user_role AS ENUM ('buyer', 'seller', 'admin');
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'banned');
CREATE TYPE product_status AS ENUM ('pending', 'approved', 'rejected', 'removed');
CREATE TYPE order_status AS ENUM ('created', 'paid', 'failed', 'refunded');
CREATE TYPE withdrawal_status AS ENUM ('pending', 'approved', 'rejected', 'paid');
CREATE TYPE transaction_type AS ENUM ('sale', 'commission', 'withdrawal', 'refund');

-- ------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(150) NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    role                user_role NOT NULL DEFAULT 'buyer',
    status              user_status NOT NULL DEFAULT 'active',
    phone               VARCHAR(20),
    avatar_url          TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_verify_token  VARCHAR(255),
    reset_token         VARCHAR(255),
    reset_token_expires TIMESTAMPTZ,
    refresh_token_hash  VARCHAR(255),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- ------------------------------------------------------------
-- SELLER PROFILE (store page info)
-- ------------------------------------------------------------
CREATE TABLE seller_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    store_name      VARCHAR(150) NOT NULL,
    store_slug      VARCHAR(160) UNIQUE NOT NULL,
    bio             TEXT,
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    bank_account_no VARCHAR(50),
    bank_ifsc       VARCHAR(20),
    bank_holder     VARCHAR(150),
    upi_id          VARCHAR(100),
    rating_avg      NUMERIC(3,2) NOT NULL DEFAULT 0,
    rating_count    INTEGER NOT NULL DEFAULT 0,
    total_sales     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_seller_profiles_slug ON seller_profiles(store_slug);

-- ------------------------------------------------------------
-- CATEGORIES
-- ------------------------------------------------------------
CREATE TABLE categories (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) UNIQUE NOT NULL,
    slug        VARCHAR(120) UNIQUE NOT NULL,
    description TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- PRODUCTS
-- ------------------------------------------------------------
CREATE TABLE products (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    seller_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category_id       UUID NOT NULL REFERENCES categories(id),
    title             VARCHAR(255) NOT NULL,
    slug              VARCHAR(280) UNIQUE NOT NULL,
    description       TEXT NOT NULL,
    subject           VARCHAR(150),
    course            VARCHAR(150),
    university        VARCHAR(150),
    semester          VARCHAR(50),
    language          VARCHAR(50) DEFAULT 'English',
    product_type      VARCHAR(50) NOT NULL, -- Handwritten Notes, PDF Notes, PYQ, etc.
    price             NUMERIC(10,2) NOT NULL CHECK (price >= 0),
    mrp               NUMERIC(10,2) CHECK (mrp >= 0),
    cover_image_key   TEXT,        -- storage key, not public URL
    preview_file_key  TEXT,        -- watermarked/limited preview
    original_file_key TEXT NOT NULL, -- full file, never exposed directly
    file_size_bytes   BIGINT,
    page_count        INTEGER,
    status            product_status NOT NULL DEFAULT 'pending',
    rejection_reason  TEXT,
    rating_avg        NUMERIC(3,2) NOT NULL DEFAULT 0,
    rating_count      INTEGER NOT NULL DEFAULT 0,
    sales_count       INTEGER NOT NULL DEFAULT 0,
    view_count        INTEGER NOT NULL DEFAULT 0,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_products_seller ON products(seller_id);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_status ON products(status);
CREATE INDEX idx_products_search ON products USING GIN (
    to_tsvector('english', title || ' ' || coalesce(subject,'') || ' ' || coalesce(course,'') || ' ' || coalesce(university,''))
);

-- ------------------------------------------------------------
-- CART
-- ------------------------------------------------------------
CREATE TABLE cart_items (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, product_id)
);

-- ------------------------------------------------------------
-- WISHLIST
-- ------------------------------------------------------------
CREATE TABLE wishlist_items (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, product_id)
);

-- ------------------------------------------------------------
-- ORDERS (one order can contain multiple products — order_items)
-- ------------------------------------------------------------
CREATE TABLE orders (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    buyer_id              UUID NOT NULL REFERENCES users(id),
    order_number          VARCHAR(30) UNIQUE NOT NULL,
    subtotal              NUMERIC(10,2) NOT NULL,
    total_amount          NUMERIC(10,2) NOT NULL,
    status                order_status NOT NULL DEFAULT 'created',
    razorpay_order_id     VARCHAR(100) UNIQUE,
    razorpay_payment_id   VARCHAR(100),
    razorpay_signature    VARCHAR(255),
    paid_at               TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_orders_buyer ON orders(buyer_id);
CREATE INDEX idx_orders_razorpay ON orders(razorpay_order_id);
CREATE INDEX idx_orders_status ON orders(status);

CREATE TABLE order_items (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id          UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id        UUID NOT NULL REFERENCES products(id),
    seller_id         UUID NOT NULL REFERENCES users(id),
    unit_price        NUMERIC(10,2) NOT NULL,
    commission_rate   NUMERIC(5,2) NOT NULL DEFAULT 10.00, -- percent
    commission_amount NUMERIC(10,2) NOT NULL,
    seller_earning    NUMERIC(10,2) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_order_items_order ON order_items(order_id);
CREATE INDEX idx_order_items_seller ON order_items(seller_id);
CREATE INDEX idx_order_items_product ON order_items(product_id);

-- ------------------------------------------------------------
-- ENTITLEMENTS — proof buyer purchased a product (drives secure downloads)
-- ------------------------------------------------------------
CREATE TABLE entitlements (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    buyer_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id   UUID NOT NULL REFERENCES products(id),
    order_id     UUID NOT NULL REFERENCES orders(id),
    download_count INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(buyer_id, product_id)
);
CREATE INDEX idx_entitlements_buyer ON entitlements(buyer_id);

-- ------------------------------------------------------------
-- WALLET
-- ------------------------------------------------------------
CREATE TABLE wallets (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    seller_id          UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    available_balance  NUMERIC(12,2) NOT NULL DEFAULT 0,
    pending_balance    NUMERIC(12,2) NOT NULL DEFAULT 0,
    total_earned       NUMERIC(12,2) NOT NULL DEFAULT 0,
    total_withdrawn    NUMERIC(12,2) NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE wallet_transactions (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id      UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    type           transaction_type NOT NULL,
    amount         NUMERIC(12,2) NOT NULL, -- positive = credit, negative = debit
    reference_id   UUID, -- order_item id or withdrawal id
    description    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_wallet_tx_wallet ON wallet_transactions(wallet_id);

-- ------------------------------------------------------------
-- WITHDRAWALS
-- ------------------------------------------------------------
CREATE TABLE withdrawals (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    seller_id       UUID NOT NULL REFERENCES users(id),
    wallet_id       UUID NOT NULL REFERENCES wallets(id),
    amount          NUMERIC(12,2) NOT NULL CHECK (amount > 0),
    status          withdrawal_status NOT NULL DEFAULT 'pending',
    admin_note      TEXT,
    processed_by    UUID REFERENCES users(id),
    processed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_withdrawals_seller ON withdrawals(seller_id);
CREATE INDEX idx_withdrawals_status ON withdrawals(status);

-- ------------------------------------------------------------
-- REVIEWS
-- ------------------------------------------------------------
CREATE TABLE reviews (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    buyer_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    order_id    UUID NOT NULL REFERENCES orders(id),
    rating      SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(product_id, buyer_id)
);
CREATE INDEX idx_reviews_product ON reviews(product_id);

-- ------------------------------------------------------------
-- REPORTS (flag illegal/copyrighted content)
-- ------------------------------------------------------------
CREATE TABLE reports (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_id  UUID REFERENCES users(id),
    product_id   UUID REFERENCES products(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    status       VARCHAR(30) NOT NULL DEFAULT 'open', -- open, reviewed, dismissed
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- AUDIT LOG (admin actions)
-- ------------------------------------------------------------
CREATE TABLE admin_audit_log (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_id    UUID NOT NULL REFERENCES users(id),
    action      VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id   UUID,
    meta        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- SEED CATEGORIES
-- ------------------------------------------------------------
INSERT INTO categories (name, slug, description) VALUES
('School', 'school', 'School level notes and study material'),
('College', 'college', 'General college / undergraduate notes'),
('Medical', 'medical', 'Medical and MBBS study material'),
('Engineering', 'engineering', 'Engineering notes and technical material'),
('Nursing', 'nursing', 'Nursing study material'),
('NEET', 'neet', 'NEET exam preparation'),
('JEE', 'jee', 'JEE exam preparation'),
('UPSC', 'upsc', 'UPSC civil services preparation'),
('SSC', 'ssc', 'SSC exam preparation'),
('Others', 'others', 'Other educational material');

-- ------------------------------------------------------------
-- TRIGGERS: auto-update updated_at
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_products_updated_at BEFORE UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_orders_updated_at BEFORE UPDATE ON orders
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_seller_profiles_updated_at BEFORE UPDATE ON seller_profiles
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
