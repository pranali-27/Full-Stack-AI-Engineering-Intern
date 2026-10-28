require("dotenv").config();
const bcrypt = require("bcryptjs");
const fs = require("node:fs");
const path = require("node:path");
const { initDb, db } = require("../src/db");
initDb();
const email = "demo@example.com";
const password = "DemoPass123!";
let user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
if (!user) {
  const info = db.prepare("INSERT INTO users(email,password_hash,quota_bytes) VALUES(?,?,?)")
    .run(email, bcrypt.hashSync(password, 10), Number(process.env.DEFAULT_QUOTA_BYTES || 104857600));
  user = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
}
const folder = db.prepare("SELECT id FROM folders WHERE owner_id=? AND name='Sample Documents' AND parent_id IS NULL").get(user.id);
if (!folder) db.prepare("INSERT INTO folders(owner_id,parent_id,name) VALUES(?,NULL,'Sample Documents')").run(user.id);
console.log("Demo login: demo@example.com / DemoPass123!");
console.log("This account is for local development only. Change credentials before deploying.");
