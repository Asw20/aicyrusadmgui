# Cyrus Console

A responsive web administration app for Cyrus IMAP. Includes account registration and sign-in, isolated workspaces, a dashboard, personal and shared mailbox management, quotas, ACL editing, and an activity log. Start with persistent demo data or connect to a real Cyrus server over certificate-verified IMAPS.

## Run

Requires Python 3.12 or newer. The application uses only the Python standard library; no dependency installation or frontend build is required.

```sh
cd /workspace/aicyrusadmgui
python3 server.py
```

The default listener is `127.0.0.1:8000`. Open the application in your browser and create a workspace with an email and a password of at least 10 characters. Each workspace receives its own demo mailboxes. No default credentials are installed.

```sh
# Optional configuration for a container or private deployment:
HOST=0.0.0.0 PORT=8000 python3 server.py
```

`HOST` and `PORT` control the listener. `CYRUS_DATA_DIR` selects the persistent data directory (default `.data` in the checkout). Back up its SQLite database. `COOKIE_SECURE=1` enables secure session cookies when served over HTTPS. `CYRUS_ALLOWED_HOSTS=mail.example.com,imap.example.com` restricts user-selected IMAP destinations to an exact host allowlist. Set it and constrain network egress before hosting for untrusted users. Private CA installations can use Python/OpenSSL’s `SSL_CERT_FILE` trust configuration; TLS verification is never disabled.

## Workflows

- **Users:** list, search, provision personal mailboxes, rename mailbox users, set storage quotas, manage access, and delete mailboxes with exact-name confirmation.
- **Mailboxes:** list, search, filter personal/shared mailboxes, create, rename, inspect/set quota, delete, and edit permissions.
- **Access control:** inspect explicit ACL entries, apply read-only/read-write/admin presets or individual IMAP rights, and remove entries with confirmation.
- **Activity:** view the latest 30 successful mailbox/ACL changes performed through this workspace, with demo/live labels. Changes made by other tools are not recorded.
- **Server settings:** test an IMAPS administrator connection or return to demo mode. Failed connection attempts preserve the previous connection.

## Live Cyrus requirements and boundaries

Use an administrator account from your Cyrus `admins` configuration. The application server needs direct TCP access to the IMAPS endpoint (usually port 993). The Cyrus server must advertise `ACL`; quota operations also require `QUOTA`. Connections use validated TLS certificates, a 12-second connection timeout, and a fresh IMAP login for each request.

The interface maps to `cyradm` operations `listmailbox`, `createmailbox`, `renamemailbox`, `deletemailbox`, `listacl`, `setacl`, `deleteacl`, `listquota`, and `setquota`. It is not a complete replacement for advanced cyradm operations such as annotations, partitions, subscriptions, transfers, or server-side maintenance.

**Cyrus mailboxes are separate from authentication identities.** Creating `user.alex` provisions mail storage; it does not create a SASL/LDAP login or set a password. Renaming or deleting a mailbox does not rename or delete the corresponding authentication identity. Manage those in the existing authentication provider. The user directory identifies top-level mailboxes in the server’s `user` namespace using its reported hierarchy separator. Alternative Cyrus namespace configurations may require using the mailbox screen directly.

Mailbox names and principals currently support printable ASCII (including Cyrus modified UTF-7 names entered explicitly). The app does not perform automatic Unicode/modified UTF-7 conversion. Live rename/delete behavior is governed by Cyrus policies and privileges; user renames may require `allowusermoves`. Live errors appear in the interface. Deleting a nonempty mailbox may remove messages permanently; child mailboxes should be removed first. Setting a live quota creates or updates the quota root named for that mailbox; existing shared quota roots require particular care. ACL entries show explicit rights; effective access may also depend on implicit owner rights, groups, and server configuration. Quotas are loaded on demand for live mailbox details rather than making one IMAP quota request per directory row.

## Persistence and deployment

Workspace accounts use salted scrypt password hashes. Demo data and activity records are tenant-scoped SQLite rows. Admin connection credentials and application sessions remain in process memory; they expire after eight hours and do not survive restart. Reconnect a live server after signing back in. Each account is currently a single-operator workspace; team invitations, role-based membership, password reset, email verification, billing, and external identity-provider provisioning are not implemented.

This is a working application foundation for private administration, not a hardened public SaaS deployment. For production, serve through an HTTPS reverse proxy, set `COOKIE_SECURE=1` and the IMAP host allowlist, restrict signup and ingress to authorized administrators, and apply edge rate limits. The included HTTP server and in-memory session/rate-limit stores are intended for one application process. Multi-instance hosting needs a production server, shared session storage, centralized audit logging, and a managed database. Never expose an unrestricted IMAP connection proxy to public users.

## Validation

```sh
python3 -m unittest discover -s tests -v
node --check static/app.js  # optional JS syntax validation
```

The automated suite exercises authentication/logout, tenant isolation, mailbox creation/rename/deletion, recursive demo renames, quotas, ACL updates/removal, input validation, and cross-origin request rejection. The live IMAP adapter tests use a mocked Cyrus endpoint to verify response parsing and TLS settings. Live server compatibility still needs an accessible Cyrus instance and admin credentials.

Optional browser smoke test (requires Playwright and Chromium, neither is needed to run the app):

```sh
# Start python3 server.py first, then:
CHROMIUM_PATH=/usr/bin/chromium python3 tests/browser_smoke.py
```
