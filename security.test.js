const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const request = require("supertest");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cloudnest-test-"));
process.env.DATABASE_PATH = path.join(tmp, "test.db");
process.env.STORAGE_PATH = path.join(tmp, "storage");
process.env.SESSION_SECRET = "test-session-secret-that-is-long";
process.env.DEFAULT_QUOTA_BYTES = "20";
process.env.MAX_UPLOAD_BYTES = "1000";
const { initDb, db } = require("../src/db");
initDb();
const { createApp } = require("../src/app");
const app = createApp();
let agentA, agentB, fileId, folderId;

async function register(agent, email) {
  const r = await agent.post("/api/auth/register").send({ email, password: "Password123!" });
  assert.equal(r.status, 201);
}
test("setup creates two isolated users", async () => {
  agentA = request.agent(app); agentB = request.agent(app);
  await register(agentA, "a@example.com"); await register(agentB, "b@example.com");
});
test("user can create a folder and upload a small file", async () => {
  const f = await agentA.post("/api/folders").send({ name: "Docs" });
  assert.equal(f.status, 201); folderId = f.body.id;
  const u = await agentA.post("/api/upload").field("folderId", String(folderId)).attach("file", Buffer.from("hello"), "hello.txt");
  assert.equal(u.status, 201); fileId = u.body.id;
});
test("another user cannot preview or rename a guessed file ID", async () => {
  const p = await agentB.get(`/api/files/${fileId}/preview`);
  assert.equal(p.status, 404);
  const r = await agentB.patch(`/api/files/${fileId}`).send({ name: "stolen.txt" });
  assert.equal(r.status, 404);
});
test("server rejects upload that exceeds quota without charging usage", async () => {
  const before = (await agentA.get("/api/me")).body.user.usedBytes;
  const r = await agentA.post("/api/upload").attach("file", Buffer.from("this is larger than remaining quota"), "large.txt");
  assert.equal(r.status, 413);
  const after = (await agentA.get("/api/me")).body.user.usedBytes;
  assert.equal(after, before);
});
test("invalid folder names are rejected", async () => {
  const r = await agentA.post("/api/folders").send({ name: "../bad" });
  assert.equal(r.status, 400);
});
test("file deletion is soft delete and owner can restore within retention window", async () => {
  const del = await agentA.delete(`/api/files/${fileId}`);
  assert.equal(del.status, 200);
  const trash = await agentA.get("/api/trash");
  assert.ok(trash.body.items.some(i => i.id === fileId && i.kind === "file"));
  const restore = await agentA.post(`/api/trash/file/${fileId}/restore`);
  assert.equal(restore.status, 200);
});
test("folder cannot be moved into itself", async () => {
  const r = await agentA.patch(`/api/folders/${folderId}`).send({ parentId: folderId });
  assert.equal(r.status, 400);
});
test("expired share links are rejected", async () => {
  const s = await agentA.post("/api/shares").send({ fileId, expiresAt: new Date(Date.now()+60000).toISOString() });
  assert.equal(s.status, 201);
  const token = s.body.token;
  db.prepare("UPDATE share_links SET expires_at=? WHERE token_hash=?")
    .run(new Date(Date.now()-60000).toISOString(), require("../src/utils").tokenHash(token));
  const r = await request(app).get(`/s/${token}`);
  assert.equal(r.status, 404);
});
test.after(() => { try { db.close(); } catch {} fs.rmSync(tmp, { recursive: true, force: true }); });
