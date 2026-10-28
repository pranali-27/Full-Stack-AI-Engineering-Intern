const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { db } = require("./db");
const { validName, tokenHash, nowIso, isExpired, safeUser } = require("./utils");

const storagePath = path.resolve(process.env.STORAGE_PATH || "./storage");
fs.mkdirSync(storagePath, { recursive: true });
const maxUpload = Number(process.env.MAX_UPLOAD_BYTES || 104857600);
const defaultQuota = Number(process.env.DEFAULT_QUOTA_BYTES || 104857600);
const baseUrl = process.env.APP_BASE_URL || "http://localhost:4000";

function httpError(status, message) {
  const e = new Error(message); e.status = status; return e;
}
function createApp() {
  const app = express();
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use(session({
    store: new SQLiteStore({ db: "sessions.db", dir: path.resolve("./data") }),
    secret: process.env.SESSION_SECRET || "development-only-change-me",
    resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 86400000 }
  }));
  app.use(express.static(path.resolve(__dirname, "../public")));

  const auth = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: "Please log in first." });
    next();
  };
  const ownedFile = (userId, id) => db.prepare("SELECT * FROM files WHERE id=? AND owner_id=? AND deleted_at IS NULL").get(id, userId);
  const ownedFolder = (userId, id) => db.prepare("SELECT * FROM folders WHERE id=? AND owner_id=? AND deleted_at IS NULL").get(id, userId);
  const quotaReserve = db.transaction((userId, bytes) => {
    const u = db.prepare("SELECT quota_bytes, used_bytes FROM users WHERE id=?").get(userId);
    if (!u || bytes < 0 || u.used_bytes + bytes > u.quota_bytes) throw httpError(413, "Storage limit exceeded. Delete files or increase your quota.");
    db.prepare("UPDATE users SET used_bytes=used_bytes+? WHERE id=?").run(bytes, userId);
  });

  app.post("/api/auth/register", async (req, res, next) => {
    try {
      const email = String(req.body.email || "").trim().toLowerCase();
      const password = String(req.body.password || "");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw httpError(400, "Enter a valid email address.");
      if (password.length < 8 || password.length > 128) throw httpError(400, "Password must be 8–128 characters.");
      if (db.prepare("SELECT id FROM users WHERE email=?").get(email)) throw httpError(409, "An account with this email already exists.");
      const hash = await bcrypt.hash(password, 12);
      const info = db.prepare("INSERT INTO users(email,password_hash,quota_bytes) VALUES(?,?,?)").run(email, hash, defaultQuota);
      req.session.userId = Number(info.lastInsertRowid);
      res.status(201).json({ user: { id: Number(info.lastInsertRowid), email, quotaBytes: defaultQuota, usedBytes: 0 } });
    } catch (e) { next(e); }
  });
  app.post("/api/auth/login", async (req, res, next) => {
    try {
      const email = String(req.body.email || "").trim().toLowerCase();
      const password = String(req.body.password || "");
      const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
      if (!user || !(await bcrypt.compare(password, user.password_hash))) throw httpError(401, "Email or password is incorrect.");
      req.session.userId = user.id;
      res.json({ user: safeUser(user) });
    } catch (e) { next(e); }
  });
  app.post("/api/auth/logout", auth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
  app.get("/api/me", auth, (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);
    if (!user) return res.status(401).json({ error: "Session expired. Please log in again." });
    res.json({ user: safeUser(user) });
  });

  app.get("/api/items", auth, (req, res, next) => {
    try {
      const uid = req.session.userId;
      const folderId = req.query.folderId ? Number(req.query.folderId) : null;
      if (folderId && !ownedFolder(uid, folderId)) throw httpError(404, "Folder not found.");
      const folders = db.prepare("SELECT id,name,parent_id,created_at FROM folders WHERE owner_id=? AND parent_id IS ? AND deleted_at IS NULL ORDER BY name").all(uid, folderId);
      const files = db.prepare("SELECT id,name,folder_id,size_bytes,mime_type,created_at FROM files WHERE owner_id=? AND folder_id IS ? AND deleted_at IS NULL ORDER BY name").all(uid, folderId);
      res.json({ folders, files });
    } catch (e) { next(e); }
  });
  app.post("/api/folders", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, name = String(req.body.name || "").trim();
      const parentId = req.body.parentId ? Number(req.body.parentId) : null;
      if (!validName(name)) throw httpError(400, "Folder name must be 1–180 characters and cannot contain slashes.");
      if (parentId && !ownedFolder(uid, parentId)) throw httpError(404, "Parent folder not found.");
      const result = db.prepare("INSERT INTO folders(owner_id,parent_id,name) VALUES(?,?,?)").run(uid, parentId, name);
      res.status(201).json({ id: Number(result.lastInsertRowid), name, parentId });
    } catch (e) { next(e); }
  });
  app.patch("/api/folders/:id", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, id = Number(req.params.id), folder = ownedFolder(uid, id);
      if (!folder) throw httpError(404, "Folder not found.");
      if (req.body.name !== undefined) {
        const name = String(req.body.name).trim();
        if (!validName(name)) throw httpError(400, "Invalid folder name.");
        db.prepare("UPDATE folders SET name=? WHERE id=? AND owner_id=?").run(name, id, uid);
      }
      if (req.body.parentId !== undefined) {
        const parentId = req.body.parentId ? Number(req.body.parentId) : null;
        if (parentId && !ownedFolder(uid, parentId)) throw httpError(404, "Destination folder not found.");
        if (parentId === id) throw httpError(400, "A folder cannot be moved inside itself.");
        if (parentId) {
          let cursor = ownedFolder(uid, parentId);
          while (cursor && cursor.parent_id) {
            if (cursor.parent_id === id) throw httpError(400, "Cannot move a folder into its own descendant.");
            cursor = ownedFolder(uid, cursor.parent_id);
          }
        }
        db.prepare("UPDATE folders SET parent_id=? WHERE id=? AND owner_id=?").run(parentId, id, uid);
      }
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  const upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, storagePath),
      filename: (_req, _file, cb) => cb(null, crypto.randomUUID())
    }),
    limits: { fileSize: maxUpload, files: 1 }
  });
  app.post("/api/upload", auth, (req, res, next) => {
    upload.single("file")(req, res, async err => {
      if (err) {
        if (req.file?.path) fs.rmSync(req.file.path, { force: true });
        const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
        return res.status(status).json({ error: status === 413 ? "File exceeds the maximum upload size." : "Upload could not be processed." });
      }
      try {
        const uid = req.session.userId;
        if (!req.file) throw httpError(400, "Choose a file to upload.");
        const folderId = req.body.folderId ? Number(req.body.folderId) : null;
        if (folderId && !ownedFolder(uid, folderId)) throw httpError(404, "Destination folder not found.");
        const size = req.file.size;
        try { quotaReserve(uid, size); }
        catch (e) { fs.rmSync(req.file.path, { force: true }); throw e; }
        const name = path.basename(req.file.originalname || "upload").slice(0, 180);
        const mime = req.file.mimetype || "application/octet-stream";
        try {
          const info = db.prepare("INSERT INTO files(owner_id,folder_id,name,object_key,size_bytes,mime_type) VALUES(?,?,?,?,?,?)")
            .run(uid, folderId, name, path.basename(req.file.path), size, mime);
          res.status(201).json({ id: Number(info.lastInsertRowid), name, sizeBytes: size, mimeType: mime });
        } catch (e) {
          db.prepare("UPDATE users SET used_bytes=MAX(0,used_bytes-?) WHERE id=?").run(size, uid);
          fs.rmSync(req.file.path, { force: true });
          throw e;
        }
      } catch (e) { next(e); }
    });
  });

  app.patch("/api/files/:id", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, id = Number(req.params.id), file = ownedFile(uid, id);
      if (!file) throw httpError(404, "File not found.");
      if (req.body.name !== undefined) {
        const name = String(req.body.name).trim();
        if (!validName(name)) throw httpError(400, "Invalid file name.");
        db.prepare("UPDATE files SET name=? WHERE id=? AND owner_id=?").run(name, id, uid);
      }
      if (req.body.folderId !== undefined) {
        const folderId = req.body.folderId ? Number(req.body.folderId) : null;
        if (folderId && !ownedFolder(uid, folderId)) throw httpError(404, "Destination folder not found.");
        db.prepare("UPDATE files SET folder_id=? WHERE id=? AND owner_id=?").run(folderId, id, uid);
      }
      res.json({ ok: true });
    } catch (e) { next(e); }
  });
  app.delete("/api/files/:id", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, file = ownedFile(uid, Number(req.params.id));
      if (!file) throw httpError(404, "File not found.");
      db.prepare("UPDATE files SET deleted_at=? WHERE id=? AND owner_id=?").run(nowIso(), file.id, uid);
      res.json({ ok: true, message: "File moved to trash for 7 days." });
    } catch (e) { next(e); }
  });
  app.delete("/api/folders/:id", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, folder = ownedFolder(uid, Number(req.params.id));
      if (!folder) throw httpError(404, "Folder not found.");
      const stamp = nowIso();
      const markTree = db.transaction((folderId) => {
        const children = db.prepare("SELECT id FROM folders WHERE owner_id=? AND parent_id=? AND deleted_at IS NULL").all(uid, folderId);
        for (const child of children) markTree(child.id);
        db.prepare("UPDATE folders SET deleted_at=? WHERE id=? AND owner_id=?").run(stamp, folderId, uid);
        db.prepare("UPDATE files SET deleted_at=? WHERE owner_id=? AND folder_id=? AND deleted_at IS NULL").run(stamp, uid, folderId);
      });
      markTree(folder.id);
      res.json({ ok: true });
    } catch (e) { next(e); }
  });
  app.get("/api/trash", auth, (req, res) => {
    const uid = req.session.userId, cutoff = new Date(Date.now() - 7*86400000).toISOString();
    const files = db.prepare("SELECT id,name,size_bytes,deleted_at,'file' AS kind FROM files WHERE owner_id=? AND deleted_at IS NOT NULL AND deleted_at>=? ORDER BY deleted_at DESC").all(uid, cutoff);
    const folders = db.prepare("SELECT id,name,deleted_at,'folder' AS kind FROM folders WHERE owner_id=? AND deleted_at IS NOT NULL AND deleted_at>=? ORDER BY deleted_at DESC").all(uid, cutoff);
    res.json({ items: [...files, ...folders] });
  });
  app.post("/api/trash/:kind/:id/restore", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, cutoff = new Date(Date.now() - 7*86400000).toISOString();
      const { kind } = req.params, id = Number(req.params.id);
      if (kind === "file") {
        const f = db.prepare("SELECT * FROM files WHERE id=? AND owner_id=? AND deleted_at>=?").get(id, uid, cutoff);
        if (!f) throw httpError(404, "Trash item not found or retention period ended.");
        const folder = f.folder_id ? ownedFolder(uid, f.folder_id) : true;
        db.prepare("UPDATE files SET deleted_at=NULL,folder_id=? WHERE id=? AND owner_id=?").run(folder ? f.folder_id : null, id, uid);
      } else if (kind === "folder") {
        const f = db.prepare("SELECT * FROM folders WHERE id=? AND owner_id=? AND deleted_at>=?").get(id, uid, cutoff);
        if (!f) throw httpError(404, "Trash item not found or retention period ended.");
        const parent = f.parent_id ? ownedFolder(uid, f.parent_id) : true;
        db.prepare("UPDATE folders SET deleted_at=NULL,parent_id=? WHERE id=? AND owner_id=?").run(parent ? f.parent_id : null, id, uid);
      } else throw httpError(400, "Invalid trash item type.");
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  app.get("/api/files/:id/preview", auth, (req, res, next) => {
    try {
      const f = ownedFile(req.session.userId, Number(req.params.id));
      if (!f) throw httpError(404, "File not found.");
      if (!(f.mime_type.startsWith("image/") || f.mime_type === "application/pdf")) throw httpError(415, "Preview is available only for images and PDFs.");
      const full = path.join(storagePath, path.basename(f.object_key));
      if (!fs.existsSync(full)) throw httpError(404, "Stored file is missing.");
      res.setHeader("Content-Type", f.mime_type);
      res.setHeader("Content-Disposition", `inline; filename="${f.name.replace(/["\\r\\n]/g, "_")}"`);
      res.setHeader("X-Content-Type-Options", "nosniff");
      fs.createReadStream(full).pipe(res);
    } catch (e) { next(e); }
  });

  app.post("/api/shares", auth, (req, res, next) => {
    try {
      const uid = req.session.userId, file = ownedFile(uid, Number(req.body.fileId));
      if (!file) throw httpError(404, "File not found.");
      let expiresAt = null;
      if (req.body.expiresAt) {
        const d = new Date(req.body.expiresAt);
        if (Number.isNaN(d.getTime()) || d.getTime() <= Date.now()) throw httpError(400, "Expiry date must be a valid future date.");
        expiresAt = d.toISOString();
      }
      const password = req.body.password ? String(req.body.password) : "";
      if (password && (password.length < 4 || password.length > 128)) throw httpError(400, "Share password must be 4–128 characters.");
      const token = crypto.randomBytes(32).toString("base64url");
      const passwordHash = password ? bcrypt.hashSync(password, 10) : null;
      db.prepare("INSERT INTO share_links(file_id,owner_id,token_hash,password_hash,expires_at) VALUES(?,?,?,?,?)")
        .run(file.id, uid, tokenHash(token), passwordHash, expiresAt);
      res.status(201).json({ url: `${baseUrl}/s/${token}`, token });
    } catch (e) { next(e); }
  });
  app.get("/s/:token", (req, res, next) => {
    try {
      const link = db.prepare("SELECT * FROM share_links WHERE token_hash=?").get(tokenHash(String(req.params.token)));
      if (!link || link.revoked_at || isExpired(link.expires_at)) throw httpError(404, "This share link is invalid or expired.");
      const file = db.prepare("SELECT * FROM files WHERE id=? AND deleted_at IS NULL").get(link.file_id);
      if (!file) throw httpError(404, "Shared file is no longer available.");
      if (link.password_hash) {
        if (req.method !== "POST" || !req.body || !bcrypt.compareSync(String(req.body.password || ""), link.password_hash)) {
          return res.status(401).send(`<!doctype html><html><body><h2>Password required</h2><form method="post"><input name="password" type="password" required><button>Open file</button></form></body></html>`);
        }
      }
      const full = path.join(storagePath, path.basename(file.object_key));
      if (!fs.existsSync(full)) throw httpError(404, "Stored file is missing.");
      db.prepare("UPDATE share_links SET download_count=download_count+1 WHERE id=?").run(link.id);
      res.setHeader("Content-Type", file.mime_type);
      res.setHeader("Content-Disposition", `attachment; filename="${file.name.replace(/["\\r\\n]/g, "_")}"`);
      res.setHeader("X-Content-Type-Options", "nosniff");
      fs.createReadStream(full).pipe(res);
    } catch (e) { next(e); }
  });
  app.get("/api/shares/:fileId", auth, (req, res, next) => {
    try {
      const file = ownedFile(req.session.userId, Number(req.params.fileId));
      if (!file) throw httpError(404, "File not found.");
      const links = db.prepare("SELECT id,expires_at,download_count,revoked_at,created_at FROM share_links WHERE file_id=? AND owner_id=? ORDER BY id DESC").all(file.id, req.session.userId);
      res.json({ links });
    } catch (e) { next(e); }
  });
  app.delete("/api/shares/:id", auth, (req, res, next) => {
    try {
      const result = db.prepare("UPDATE share_links SET revoked_at=? WHERE id=? AND owner_id=?").run(nowIso(), Number(req.params.id), req.session.userId);
      if (!result.changes) throw httpError(404, "Share link not found.");
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  // Search across a user's active files and folders.
  app.get("/api/search", auth, (req, res) => {
    const q = String(req.query.q || "").trim().slice(0, 100);
    if (!q) return res.json({ files: [], folders: [] });
    const like = `%${q.replace(/[\\%_]/g, "\\$&")}%`;
    const files = db.prepare("SELECT id,name,folder_id,size_bytes,mime_type FROM files WHERE owner_id=? AND deleted_at IS NULL AND name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 100").all(req.session.userId, like);
    const folders = db.prepare("SELECT id,name,parent_id FROM folders WHERE owner_id=? AND deleted_at IS NULL AND name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 100").all(req.session.userId, like);
    res.json({ files, folders });
  });

  app.use((err, req, res, _next) => {
    if (res.headersSent) return;
    const status = Number(err.status || 500);
    if (status >= 500) console.error(err);
    res.status(status).json({ error: status >= 500 ? "Something went wrong. Please try again." : err.message });
  });
  return app;
}
module.exports = { createApp };
