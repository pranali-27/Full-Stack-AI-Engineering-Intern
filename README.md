# CloudNest — File Storage & Sharing App

A full-stack assignment starter for private multi-user file storage. Frontend: responsive HTML/CSS/JavaScript. Backend: Node.js + Express API. Database: SQLite. File bytes are stored in a private local directory for development.

## Features included

- Register/login with hashed passwords and HTTP-only session cookie.
- Owner-scoped file/folder operations.
- Nested folders, rename, move, soft-delete and restore.
- File upload progress bar and server-side maximum size / per-user quota checks.
- Image/PDF preview through authenticated API routes.
- Share links with optional password and expiry; successful downloads increment the counter.
- Storage usage display, cross-folder name search, and demo seed script.
- Automated security and backend tests.

## Requirements

- Node.js 20+
- npm

## Setup

```bash
cp .env.example .env
npm install
npm run seed
npm test
npm start
```

Open http://localhost:4000.

Demo login after running `npm run seed`:
- Email: `demo@example.com`
- Password: `DemoPass123!`

The demo user is for local evaluation only. Do not deploy a public app with known demo credentials.

## Environment variables

See `.env.example`. Never commit `.env`, database files, uploaded files, session database, or production secrets.

## Data model

- `users`: unique email, password hash, quota bytes and used bytes.
- `folders`: owner, parent folder, name and soft-delete timestamp.
- `files`: owner, parent folder, display name, private storage key, size, MIME type and soft-delete timestamp.
- `share_links`: owner/file, hash of a random token, optional password hash, optional expiry, download count and revocation timestamp.

SQLite foreign keys and owner-scoped lookups are used. The application does not treat opaque IDs as authorization: protected queries include the authenticated user ID.

## Important design decisions

- The server measures uploaded bytes; the browser never supplies the authoritative size.
- A database transaction reserves quota before file metadata is accepted. Failed quota checks remove the staged file and do not increase usage.
- Uploads are streamed to a private storage directory and get server-generated UUID object keys.
- Trash uses soft deletion and restore is restricted to the last seven days.
- Share tokens are random and only their SHA-256 hashes are stored. Optional passwords are bcrypt-hashed.
- Share URLs are public bearer links: anyone who has the link can use it unless a password is set. Revoke links when no longer needed.

## Automated tests

Run `npm test`. Tests cover user isolation, upload quota, invalid names, trash restore, folder-move cycle protection, and expired share links. Use the tests as a starting point and add cases for concurrency, password-protected share downloads, revoked links, malformed dates, and seven-day expiry.

## What's finished / limitations

This is a runnable starter implementation, not a production-hardened cloud storage service. Core assignment flows are represented. Before submission, manually verify every flow, extend automated coverage, and fix any gaps found during testing.

Known limitations / improvements:
- Quota reservation is transaction-protected, but concurrent multipart staging can temporarily consume disk before the quota check. For stronger production guarantees, implement a streaming upload handler that reserves a declared upper bound or streams to a bounded temporary file before final acceptance, and test concurrent uploads.
- Folder deletion soft-deletes descendants. A production-grade trash UI should restore complete folder trees and support permanent deletion after the retention period.
- Add CSRF protection, rate limits, email verification/password reset, audit logging, virus scanning, and stricter MIME signature validation.
- Use private S3-compatible object storage and a scheduled cleanup job in deployment.
- Add proper destination-folder picker in the UI instead of entering folder IDs manually.
- Configure production HTTPS, secure cookies, backups, monitoring, and secret management.

## AI tools

AI assistance (ChatGPT) was used to draft the project structure, implementation scaffolding, README and test ideas. Review and understand the code, run it locally, test each feature, and be prepared to explain the authentication, owner checks, quota logic, file storage, share links and tests.

## Deployment

No live deployment is included. Deploy only after adding production security controls and setting environment variables. Never commit secrets.
