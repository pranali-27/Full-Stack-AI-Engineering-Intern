const crypto = require("node:crypto");

function validName(name) {
  return typeof name === "string" && name.trim().length > 0 &&
    name.trim().length <= 180 && !/[\\/\\0]/.test(name);
}
function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function nowIso() { return new Date().toISOString(); }
function isExpired(date) { return Boolean(date && new Date(date).getTime() <= Date.now()); }
function safeUser(user) {
  return { id: user.id, email: user.email, quotaBytes: user.quota_bytes, usedBytes: user.used_bytes };
}
module.exports = { validName, tokenHash, nowIso, isExpired, safeUser };
