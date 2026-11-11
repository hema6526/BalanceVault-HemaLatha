# BalanceVault

> **Server-Enforced RBAC Money Movement & Cryptographically Verifiable Immutable Audit Ledger**

🌐 **Live Deployment:** https://balancevault-hemalatha-283k.onrender.com/
BalanceVault is a secure financial ledger system engineered around one core guarantee: **the wrong person cannot move money they should not, and every movement (or blocked attempt) cryptographically proves who initiated it.**

---

## 🔐 Key Integrity & Security Decisions

1. **Real Authentication & Timing-Safe Verification (`server.js`)**
   - Passwords are salted with 16 random bytes and hashed with `crypto.scryptSync`, verified using `crypto.timingSafeEqual`.
   - Sessions use HMAC-SHA256 signed bearer tokens verified on every protected `/api/*` request (`401 Unauthorized` if missing, expired, or forged).
   - Signing key comes from `process.env.AUTH_SECRET` in production or is generated as a 256-bit random key stored in `data/.secret` (gitignored).

2. **Server-Enforced Roles & Segregation of Duties (`403 Forbidden`)**
   - **`CUSTOMER`** (`alice@balancevault.internal`, `bob@balancevault.internal`):
     - Can view **only accounts they own** (`ownerUserId === req.user.id`).
     - Can send money to other accounts using the non-sensitive `/api/accounts/directory` routing list (which hides private balances).
     - Can only debit/withdraw from accounts they own. Trying to debit another person's account returns `403 Forbidden` and writes a `REJECTED` audit entry under the attacker's actor ID.
     - Self-registration (`POST /api/auth/register`) hardcodes `role = 'CUSTOMER'` on the server regardless of client payload to prevent privilege escalation.
   - **`ADMIN`** (`admin@balancevault.internal`):
     - Can provision accounts, inject external capital (`POST /api/accounts/:id/deposit`), freeze/unfreeze accounts (`PATCH /api/accounts/:id/status`), and reset demo data.
     - **Segregation of Duties:** Even an `ADMIN` cannot transfer or withdraw out of a customer-owned account (`403 Forbidden`), preventing insider account draining.
   - **`AUDITOR`** (`auditor@balancevault.internal`):
     - Read-only inspection of all accounts, full audit trail, and SHA-256 chain verification (`GET /api/ledger/verify`).
     - All money movement and mutation endpoints strictly return `403 Forbidden`.

3. **Proving "Who Moved It" in an Immutable SHA-256 Chain**
   - Every ledger entry binds the server-verified `actor` (`userId`, `email`, `role`) alongside `index`, `transactionId`, `timestamp`, `type`, `fromAccountId`, `toAccountId`, `amount`, `status`, `reason`, and `previousHash` directly into the block's **SHA-256** digest.
   - Altering an amount **or** attempting to alter who initiated a transaction immediately invalidates the chain and flags the exact `compromisedIndex` via `GET /api/ledger/verify`.

4. **Atomicity, Concurrency Mutex & Rollback**
   - All writes execute sequentially inside an async mutex queue (`acquireLock`) so parallel transfers cannot cause double-spending.
   - Overdrafts (`sender.balance < amount`) and operations on `FROZEN` accounts are blocked before any balance mutation and logged as `REJECTED`.
   - Balances are snapshotted prior to execution; any failure restores original balances and records a `FAILED` audit block.
   - Disk persistence uses write-to-temp-file + atomic `fs.renameSync` (`data/ledger.json`) to avoid partial/corrupt writes.

---

## 🧪 Demo Credentials (Pre-Seeded)

| Role | Email | Password | Permissions |
|---|---|---|---|
| **CUSTOMER** | `alice@balancevault.internal` | `Customer123!` | Owns `ACC-1001` & `ACC-1003`; transfer/withdraw own funds |
| **CUSTOMER** | `bob@balancevault.internal` | `Customer123!` | Owns `ACC-1002`; transfer/withdraw own funds |
| **ADMIN** | `admin@balancevault.internal` | `Admin123!` | Owns `ACC-1004`; create accounts, deposit, freeze/unfreeze |
| **AUDITOR** | `auditor@balancevault.internal` | `Auditor123!` | Read-only across all accounts, audit trail & SHA-256 verify |

*(One-click demo sign-in buttons are also provided on the login screen.)*

---

## 🚀 Run Locally (Any Machine with Node.js v18+)

```bash
# 1. Clone or unzip the repository
cd BalanceVault

# 2. Install dependencies
npm install

# 3. Run the automated security & ledger test suite (13 tests)
npm test

# 4. Start the server
npm start
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser.

> **Windows Portable Option:** If running from the packaged Windows bundle without global Node.js, double-click `start.bat` to launch or `test.bat` to run tests.

---

## ☁️ Deploy to Cloud (Render.com)

This repository includes `render.yaml` for zero-config Node.js deployment:
1. Push repository to GitHub.
2. Create a new **Web Service** on [Render](https://render.com) connected to your repo.
3. Build Command: `npm install` | Start Command: `node server.js`.
4. *(Recommended)* Set environment variable `AUTH_SECRET` to a random 32+ character secret.

---

## 📡 REST API Reference

### Authentication
- `POST /api/auth/login` — Authenticate and receive signed Bearer token (`{ email, password }`)
- `POST /api/auth/register` — Self-register as `CUSTOMER` with optional starting balance
- `GET /api/auth/me` — Verify token and inspect current user profile

### Protected Endpoints (`Authorization: Bearer <token>`)
- `GET /api/accounts` — List accounts (Customers see own accounts; Admin/Auditor see all)
- `GET /api/accounts/directory` — Safe recipient routing list (no private balances)
- `GET /api/accounts/:id` — Inspect single account & history (`403` if non-owner Customer)
- `POST /api/accounts` — **ADMIN only:** Provision account for a user
- `PATCH /api/accounts/:id/status` — **ADMIN only:** Freeze (`FROZEN`) or activate (`ACTIVE`) an account
- `POST /api/transfers` — **ADMIN / CUSTOMER (Owner only):** Atomic transfer with `X-Idempotency-Key` support
- `POST /api/accounts/:id/deposit` — **ADMIN only:** External capital deposit
- `POST /api/accounts/:id/withdraw` — **Owner only:** Withdraw funds
- `GET /api/audit-trail` — Role-scoped immutable audit log (`?type=`, `?status=`, `?search=`)
- `GET /api/audit-trail/:txId` — Single block + live SHA-256 proof
- `GET /api/ledger/verify` — Full Genesis-to-tip SHA-256 chain integrity verification
- `POST /api/demo/reset` — **ADMIN only:** Reset seeded state

---

## 🧪 Automated Test Coverage (`npm test`)

`tests/ledger.test.js` starts an isolated HTTP server with a temporary ledger file and tests **13 end-to-end assertions**:
- Unauthenticated `401` rejections on protected endpoints
- Password verification (`401` on wrong password) & privilege-escalation prevention on registration
- `CUSTOMER` account isolation (`403` when reading another user's account)
- Wrong-person debit blocking (`403` + `REJECTED` audit block recording attacker ID)
- Segregation of duties (`ADMIN` blocked `403` from debiting customer accounts)
- `AUDITOR` strict read-only enforcement (`403` on writes)
- `ADMIN`-only deposits & account freezing (`403` on frozen transfers)
- Authorized atomic transfers with actor-bound SHA-256 block creation
- Overdraft, self-transfer, and negative amount rejections
- 10 parallel HTTP transfers confirming concurrency mutex safety
- SHA-256 tamper detection catching altered `actor.userId`
