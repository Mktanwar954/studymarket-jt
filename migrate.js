/**
 * Runs schema.sql against the configured DATABASE_URL.
 * Usage: npm run migrate
 */
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
require("dotenv").config();

async function migrate() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
  });

  try {
    const schemaPath = path.join(__dirname, "schema.sql");
    const sql = fs.readFileSync(schemaPath, "utf8");
    console.log("Running schema.sql against database...");
    await pool.query(sql);
    console.log("✅ Migration completed successfully.");
  } catch (err) {
    console.error("❌ Migration failed:", err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

migrate();
