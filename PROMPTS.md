# BalanceVault — AI Prompts & Engineering Log

> **Pair-Programming Log (Human Architecture + AI Acceleration)** documenting how **BalanceVault** was designed, hardened, and verified.

---

## Prompt 1: Architecture & Project Setup
```text
Act as a Principal Fintech Software Engineer. Build "BalanceVault" — a secure money movement and transaction ledger system with server-enforced RBAC, immutable SHA-256 audit trails, and atomic transactions.
Stack: Node.js, Express, JSON transactional ledger with atomic temp-file writes, and responsive dark-mode HTML/CSS/JavaScript frontend. Keep everything self-contained in D:\BalanceVault.
```

## Prompt 2: Authentication & Server-Enforced Roles (RBAC)
```text
Implement real authentication and role-based access control strictly on the server in server.js:
- Use crypto.scryptSync + crypto.timingSafeEqual for salted password hashing.
- Issue HMAC-SHA256 signed bearer tokens verified on every protected endpoint (401 on missing/invalid/expired tokens).
- Enforce 3 roles: CUSTOMER, ADMIN, AUDITOR.
- Segregation of duties: Only the account's ownerUserId can transfer or withdraw from that account (even ADMIN gets 403 trying to debit a customer's account).
- CUSTOMER only sees owned accounts and scoped audit entries, while sending funds via a non-sensitive /api/accounts/directory endpoint that hides private balances.
- ADMIN can provision accounts, deposit capital, freeze/unfreeze accounts (ACTIVE/FROZEN), and reset demo state.
- AUDITOR has read-only access to all accounts, audit trail, and SHA-256 verification (403 on all writes).
- Self-registration must hardcode role = 'CUSTOMER' on the server to prevent privilege escalation.
```

## Prompt 3: Actor-Bound SHA-256 Immutable Audit Ledger & Rollback
```text
Upgrade the TransactionalLedger engine so every block binds WHO initiated it (actor.userId, actor.email, actor.role) directly into the SHA-256 hash payload alongside index, transactionId, timestamp, type, fromAccountId, toAccountId, amount, status, reason, and previousHash.
- Unauthorized attempts (403) and overdrafts (400) must leave balances untouched and append a REJECTED block identifying the actor.
- Serialize writes via an async mutex queue (acquireLock) to prevent double-spending.
- Snapshot balances before mutations and roll back automatically if execution fails.
- GET /api/ledger/verify must walk block 1..N and pinpoint compromised blocks if amount or actor is tampered.
```

## Prompt 4: Role-Aware Frontend Dashboard
```text
Update public/ (index.html, style.css, app.js) to remove any client-only ledger fallback and talk strictly to the authenticated Express API:
- Add a clean Sign-In / Register screen with one-click demo buttons for CUSTOMER (Alice, Bob), ADMIN, and AUDITOR.
- Show signed-in user role pill, RBAC permissions banner, and logout button.
- Render an "Initiated By (Actor)" column in the audit table and inside the Block Detail Inspector modal.
- Scope UI buttons by role while keeping server enforcement authoritative.
```

## Prompt 5: Automated End-to-End Security & Concurrency Tests
```text
Rewrite tests/ledger.test.js to spin up the real Express app against an isolated temporary ledger file and test 13 scenarios over HTTP:
- 401 unauthenticated blocking & invalid password rejection
- Self-registration privilege escalation guard
- Customer account isolation & 403 on unauthorized transfer/withdraw
- Segregation of duties (ADMIN blocked from debiting customer accounts)
- AUDITOR read-only enforcement
- ADMIN-only deposits and account freezing
- Overdraft, self-transfer, and negative amount rejections
- 10 parallel HTTP transfers confirming zero race conditions
- SHA-256 tamper detection when mutating actor.userId
```
