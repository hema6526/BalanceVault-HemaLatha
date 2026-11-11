/**
 * BalanceVault - Secure Money Movement & Transaction Ledger System
 * Main Express Server, Server-Enforced RBAC Auth, and Immutable Ledger Engine
 *
 * Location: D:\BalanceVault\server.js
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`);
  });
  next();
});

// Storage paths (relative to project root for portability across D:\ and cloud deployments)
const DATA_DIR = path.join(__dirname, 'data');
const DEFAULT_LEDGER_FILE = path.join(DATA_DIR, 'ledger.json');
const SECRET_FILE = path.join(DATA_DIR, '.secret');
const GENESIS_PREV_HASH = '0'.repeat(64);
const SCHEMA_VERSION = '2.0.0';
const VALID_ROLES = ['ADMIN', 'CUSTOMER', 'AUDITOR'];

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Load or generate HMAC signing secret for stateless bearer tokens.
 * Uses process.env.AUTH_SECRET in production or persists a cryptographically
 * random 256-bit key locally so tokens remain valid across restarts.
 */
function loadAuthSecret() {
  if (process.env.AUTH_SECRET && process.env.AUTH_SECRET.length >= 16) {
    return process.env.AUTH_SECRET;
  }
  if (fs.existsSync(SECRET_FILE)) {
    const existing = fs.readFileSync(SECRET_FILE, 'utf-8').trim();
    if (existing.length >= 32) return existing;
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, generated, { encoding: 'utf-8', mode: 0o600 });
  return generated;
}

const AUTH_SECRET = loadAuthSecret();

// ==========================================
// PASSWORD HASHING & TOKEN UTILITIES
// ==========================================

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, keyHex] = storedHash.split(':');
  const keyBuf = Buffer.from(keyHex, 'hex');
  const derivedBuf = crypto.scryptSync(String(password), salt, 64);
  if (keyBuf.length !== derivedBuf.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedBuf);
}

function base64UrlEncode(input) {
  return Buffer.from(input).toString('base64url');
}

function base64UrlDecode(input) {
  return Buffer.from(input, 'base64url').toString('utf-8');
}

function signToken(user, expiresInSeconds = 60 * 60 * 12) {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    iat: nowSec,
    exp: nowSec + expiresInSeconds
  };
  const encodedHeader = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createHmac('sha256', AUTH_SECRET).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, signature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(signingInput).digest('base64url');

  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp < nowSec) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function createHttpError(statusCode, message, extra = {}) {
  const err = new Error(message);
  err.statusCode = statusCode;
  Object.assign(err, extra);
  return err;
}

/**
 * Transactional Ledger Engine
 * Enforces user ownership, RBAC permissions, atomic balance updates with rollback,
 * concurrency mutex serialization, and SHA-256 hash-chained audit logs binding actor identity.
 */
class TransactionalLedger {
  constructor(filePath) {
    this.filePath = filePath;
    this.users = new Map();
    this.accounts = new Map();
    this.auditLog = [];
    this.processedIdempotencyKeys = new Set();
    this.lockQueue = Promise.resolve();
    this.init();
  }

  async acquireLock(fn) {
    let release;
    const lockPromise = new Promise(resolve => { release = resolve; });
    const currentQueue = this.lockQueue;
    this.lockQueue = this.lockQueue.then(() => lockPromise);
    await currentQueue;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  // Canonical SHA-256 digest binding the actor ("who moved it") and movement details
  calculateHash(entry) {
    const actorStr = entry.actor
      ? `${entry.actor.userId}:${entry.actor.email}:${entry.actor.role}`
      : 'SYSTEM:system:SYSTEM';

    const payload = [
      entry.index,
      entry.transactionId,
      entry.timestamp,
      entry.type,
      actorStr,
      entry.fromAccountId || 'SYSTEM',
      entry.toAccountId || 'SYSTEM',
      Number(entry.amount || 0).toFixed(2),
      entry.status,
      entry.reason || '',
      entry.previousHash
    ].join('|');

    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  init() {
    if (fs.existsSync(this.filePath)) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const data = JSON.parse(raw);
        if (data.version === SCHEMA_VERSION && Array.isArray(data.users) && Array.isArray(data.accounts) && Array.isArray(data.auditLog)) {
          this.users.clear();
          data.users.forEach(u => this.users.set(u.id, u));
          this.accounts.clear();
          data.accounts.forEach(acc => {
            this.accounts.set(acc.id, { ...acc, balance: Number(acc.balance) });
          });
          this.auditLog = data.auditLog;
          console.log(`[Ledger] Loaded v${SCHEMA_VERSION}: ${this.users.size} users, ${this.accounts.size} accounts, ${this.auditLog.length} audit entries.`);
          return;
        }
        console.log('[Ledger] Older schema detected; upgrading to v2.0.0 with RBAC users and actor audit trails...');
      } catch (err) {
        console.error('[Ledger] Failed to parse existing ledger file, re-initializing:', err.message);
      }
    }
    this.seedInitialData();
  }

  seedInitialData() {
    this.users.clear();
    this.accounts.clear();
    this.auditLog = [];
    this.processedIdempotencyKeys.clear();

    const baseTime = new Date(Date.now() - 3600000 * 72).toISOString();

    // Seed 4 users spanning all 3 roles (ADMIN, CUSTOMER, AUDITOR)
    const seedUsers = [
      {
        id: 'USR-ADMIN-1',
        name: 'Sarah Jenkins (Vault Admin)',
        email: 'admin@balancevault.internal',
        role: 'ADMIN',
        passwordHash: hashPassword('Admin123!'),
        createdAt: baseTime
      },
      {
        id: 'USR-ALICE',
        name: 'Alice Johnson',
        email: 'alice@balancevault.internal',
        role: 'CUSTOMER',
        passwordHash: hashPassword('Customer123!'),
        createdAt: baseTime
      },
      {
        id: 'USR-BOB',
        name: 'Bob Martinez',
        email: 'bob@balancevault.internal',
        role: 'CUSTOMER',
        passwordHash: hashPassword('Customer123!'),
        createdAt: baseTime
      },
      {
        id: 'USR-AUDITOR-1',
        name: 'Marcus Vance (Compliance Auditor)',
        email: 'auditor@balancevault.internal',
        role: 'AUDITOR',
        passwordHash: hashPassword('Auditor123!'),
        createdAt: baseTime
      }
    ];

    seedUsers.forEach(u => this.users.set(u.id, u));

    const adminActor = this.toActor(this.users.get('USR-ADMIN-1'));
    const aliceActor = this.toActor(this.users.get('USR-ALICE'));

    // Seed accounts owned by specific users
    const seedAccounts = [
      { id: 'ACC-1001', ownerUserId: 'USR-ALICE', name: 'Alice Checking Vault', email: 'alice@balancevault.internal', balance: 25000.00, currency: 'USD', status: 'ACTIVE' },
      { id: 'ACC-1002', ownerUserId: 'USR-BOB', name: 'Bob Operating Account', email: 'bob@balancevault.internal', balance: 14500.00, currency: 'USD', status: 'ACTIVE' },
      { id: 'ACC-1003', ownerUserId: 'USR-ALICE', name: 'Alice Escrow Reserve', email: 'alice@balancevault.internal', balance: 8200.00, currency: 'USD', status: 'ACTIVE' },
      { id: 'ACC-1004', ownerUserId: 'USR-ADMIN-1', name: 'Platform Treasury Pool', email: 'admin@balancevault.internal', balance: 45000.00, currency: 'USD', status: 'ACTIVE' }
    ];

    seedAccounts.forEach(acc => {
      this.accounts.set(acc.id, {
        ...acc,
        createdAt: baseTime,
        updatedAt: baseTime
      });

      this.appendAuditEntry({
        transactionId: `TX-INIT-${acc.id}`,
        type: 'ACCOUNT_CREATION',
        actor: adminActor,
        fromAccountId: null,
        toAccountId: acc.id,
        amount: acc.balance,
        currency: 'USD',
        status: 'SUCCESS',
        note: `Provisioned for owner ${acc.ownerUserId} with seed balance`,
        timestamp: baseTime,
        snapshot: {
          fromBalanceBefore: 0,
          fromBalanceAfter: 0,
          toBalanceBefore: 0,
          toBalanceAfter: acc.balance
        }
      });
    });

    // Seed 1 sample transfer initiated by Alice to Bob
    const t1Time = new Date(Date.now() - 3600000 * 12).toISOString();
    const acc1 = this.accounts.get('ACC-1001');
    const acc2 = this.accounts.get('ACC-1002');
    const prev1 = acc1.balance;
    const prev2 = acc2.balance;
    acc1.balance = Number((acc1.balance - 1500.00).toFixed(2));
    acc2.balance = Number((acc2.balance + 1500.00).toFixed(2));

    this.appendAuditEntry({
      transactionId: 'TX-SEEDED-901',
      type: 'TRANSFER',
      actor: aliceActor,
      fromAccountId: 'ACC-1001',
      toAccountId: 'ACC-1002',
      amount: 1500.00,
      currency: 'USD',
      status: 'SUCCESS',
      note: 'Q4 Contractor payment to Bob',
      timestamp: t1Time,
      snapshot: {
        fromBalanceBefore: prev1,
        fromBalanceAfter: acc1.balance,
        toBalanceBefore: prev2,
        toBalanceAfter: acc2.balance
      }
    });

    this.persistToDisk();
    console.log('[Ledger] Seeded RBAC users, owned accounts, and actor-bound audit trail.');
  }

  toActor(user) {
    if (!user) return { userId: 'SYSTEM', email: 'system@balancevault.internal', role: 'SYSTEM' };
    return {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    };
  }

  sanitizeUser(user) {
    if (!user) return null;
    const { passwordHash, ...safe } = user;
    return safe;
  }

  persistToDisk() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = {
      version: SCHEMA_VERSION,
      lastUpdated: new Date().toISOString(),
      users: Array.from(this.users.values()),
      accounts: Array.from(this.accounts.values()),
      auditLog: this.auditLog
    };

    const tempFile = `${this.filePath}.tmp.${Date.now()}.${Math.random().toString(16).slice(2, 8)}`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tempFile, this.filePath);
  }

  appendAuditEntry(entryData) {
    const index = this.auditLog.length + 1;
    const previousHash = this.auditLog.length > 0
      ? this.auditLog[this.auditLog.length - 1].hash
      : GENESIS_PREV_HASH;

    const entry = {
      index,
      transactionId: entryData.transactionId || `TX-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
      type: entryData.type,
      actor: entryData.actor || { userId: 'SYSTEM', email: 'system@balancevault.internal', role: 'SYSTEM' },
      fromAccountId: entryData.fromAccountId || null,
      toAccountId: entryData.toAccountId || null,
      amount: Number(Number(entryData.amount || 0).toFixed(2)),
      currency: entryData.currency || 'USD',
      status: entryData.status,
      reason: entryData.reason || null,
      note: entryData.note || '',
      timestamp: entryData.timestamp || new Date().toISOString(),
      previousHash,
      hash: '',
      snapshot: entryData.snapshot || null
    };

    entry.hash = this.calculateHash(entry);
    this.auditLog.push(entry);
    return entry;
  }

  // ==========================================
  // USER AUTHENTICATION & REGISTRATION
  // ==========================================

  findUserByEmail(email) {
    if (!email) return null;
    const normalized = email.trim().toLowerCase();
    for (const user of this.users.values()) {
      if (user.email.toLowerCase() === normalized) return user;
    }
    return null;
  }

  findUserById(userId) {
    return this.users.get(userId) || null;
  }

  authenticateUser(email, password) {
    if (!email || !password) {
      throw createHttpError(400, 'Email and password are required.');
    }
    const user = this.findUserByEmail(email);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      throw createHttpError(401, 'Invalid email or password.');
    }
    const token = signToken(user);
    return { token, user: this.sanitizeUser(user) };
  }

  /**
   * Public self-registration ALWAYS creates a CUSTOMER (never ADMIN/AUDITOR)
   * to prevent privilege escalation from client payloads.
   */
  async registerCustomer({ name, email, password, initialDeposit = 0 }) {
    return this.acquireLock(async () => {
      if (!name || typeof name !== 'string' || !name.trim()) {
        throw createHttpError(400, 'Full name is required.');
      }
      if (!email || typeof email !== 'string' || !email.includes('@')) {
        throw createHttpError(400, 'A valid email address is required.');
      }
      if (!password || String(password).length < 6) {
        throw createHttpError(400, 'Password must be at least 6 characters.');
      }
      if (this.findUserByEmail(email)) {
        throw createHttpError(409, 'An account with this email already exists.');
      }

      const initBal = Number(initialDeposit) || 0;
      if (!Number.isFinite(initBal) || initBal < 0 || initBal > 10000) {
        throw createHttpError(400, 'Self-registered starting balance must be between $0.00 and $10,000.00.');
      }

      const userId = `USR-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
      const now = new Date().toISOString();
      const user = {
        id: userId,
        name: name.trim(),
        email: email.trim().toLowerCase(),
        role: 'CUSTOMER', // Hardcoded server-side; ignores any client role field
        passwordHash: hashPassword(password),
        createdAt: now
      };
      this.users.set(userId, user);

      // Provision a default personal vault account for the newly registered customer
      const accountId = this.generateNextAccountId();
      const account = {
        id: accountId,
        ownerUserId: userId,
        name: `${user.name} Primary Vault`,
        email: user.email,
        balance: Number(initBal.toFixed(2)),
        currency: 'USD',
        status: 'ACTIVE',
        createdAt: now,
        updatedAt: now
      };
      this.accounts.set(accountId, account);

      this.appendAuditEntry({
        type: 'ACCOUNT_CREATION',
        actor: this.toActor(user),
        fromAccountId: null,
        toAccountId: accountId,
        amount: account.balance,
        currency: 'USD',
        status: 'SUCCESS',
        note: `Customer self-registered & provisioned ${accountId}`,
        snapshot: { fromBalanceBefore: 0, fromBalanceAfter: 0, toBalanceBefore: 0, toBalanceAfter: account.balance }
      });

      this.persistToDisk();
      const token = signToken(user);
      return { token, user: this.sanitizeUser(user), account };
    });
  }

  generateNextAccountId() {
    let idNum = 1001 + this.accounts.size;
    let id = `ACC-${idNum}`;
    while (this.accounts.has(id)) {
      idNum++;
      id = `ACC-${idNum}`;
    }
    return id;
  }

  // ==========================================
  // ACCOUNT QUERIES & MANAGEMENT
  // ==========================================

  getAccountsForUser(requestUser, search = '') {
    let list = Array.from(this.accounts.values());

    // Role enforcement: CUSTOMER only sees accounts they own; ADMIN & AUDITOR see all
    if (requestUser.role === 'CUSTOMER') {
      list = list.filter(acc => acc.ownerUserId === requestUser.id);
    }

    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(acc =>
        acc.id.toLowerCase().includes(q) ||
        acc.name.toLowerCase().includes(q) ||
        acc.email.toLowerCase().includes(q) ||
        (acc.ownerUserId && acc.ownerUserId.toLowerCase().includes(q))
      );
    }

    return list.map(acc => {
      const owner = this.users.get(acc.ownerUserId);
      return {
        ...acc,
        ownerName: owner ? owner.name : 'Unknown'
      };
    });
  }

  /**
   * Public recipient directory returns ONLY non-sensitive routing metadata
   * (no private balances or emails) so customers can send funds to others safely.
   */
  getRecipientDirectory() {
    return Array.from(this.accounts.values()).map(acc => {
      const owner = this.users.get(acc.ownerUserId);
      return {
        id: acc.id,
        name: acc.name,
        ownerName: owner ? owner.name : 'Unknown',
        status: acc.status,
        currency: acc.currency
      };
    });
  }

  getAccountAuthorized(id, requestUser) {
    const account = this.accounts.get(id);
    if (!account) {
      throw createHttpError(404, `Account '${id}' not found.`);
    }
    if (requestUser.role === 'CUSTOMER' && account.ownerUserId !== requestUser.id) {
      throw createHttpError(403, `Forbidden: you do not have permission to view account '${id}'.`);
    }
    return account;
  }

  async createAccount({ name, email, ownerUserId, initialBalance = 0, currency = 'USD', actorUser }) {
    return this.acquireLock(async () => {
      if (!actorUser || actorUser.role !== 'ADMIN') {
        throw createHttpError(403, 'Forbidden: only ADMIN users can provision accounts.');
      }
      if (!name || typeof name !== 'string' || !name.trim()) {
        throw createHttpError(400, 'Account label / holder name is required.');
      }

      let owner = null;
      if (ownerUserId) {
        owner = this.users.get(ownerUserId);
        if (!owner) {
          throw createHttpError(404, `Owner user '${ownerUserId}' does not exist.`);
        }
      } else if (email) {
        owner = this.findUserByEmail(email);
        if (!owner) {
          throw createHttpError(404, `No registered user found with email '${email}'.`);
        }
      } else {
        owner = actorUser;
      }

      const balanceNum = Number(initialBalance) || 0;
      if (!Number.isFinite(balanceNum) || balanceNum < 0) {
        throw createHttpError(400, 'Initial balance cannot be negative.');
      }

      const id = this.generateNextAccountId();
      const now = new Date().toISOString();
      const account = {
        id,
        ownerUserId: owner.id,
        name: name.trim(),
        email: owner.email,
        balance: Number(balanceNum.toFixed(2)),
        currency: String(currency || 'USD').toUpperCase(),
        status: 'ACTIVE',
        createdAt: now,
        updatedAt: now
      };

      this.accounts.set(id, account);

      const auditEntry = this.appendAuditEntry({
        type: 'ACCOUNT_CREATION',
        actor: this.toActor(actorUser),
        fromAccountId: null,
        toAccountId: id,
        amount: account.balance,
        currency: account.currency,
        status: 'SUCCESS',
        note: `Provisioned by ${actorUser.email} for owner ${owner.id}`,
        snapshot: {
          fromBalanceBefore: 0,
          fromBalanceAfter: 0,
          toBalanceBefore: 0,
          toBalanceAfter: account.balance
        }
      });

      this.persistToDisk();
      return { account, auditEntry };
    });
  }

  async setAccountStatus({ accountId, status, reason = '', actorUser }) {
    return this.acquireLock(async () => {
      if (!actorUser || actorUser.role !== 'ADMIN') {
        throw createHttpError(403, 'Forbidden: only ADMIN users can freeze or unfreeze accounts.');
      }
      const nextStatus = String(status || '').toUpperCase();
      if (nextStatus !== 'ACTIVE' && nextStatus !== 'FROZEN') {
        throw createHttpError(400, 'Status must be ACTIVE or FROZEN.');
      }
      const account = this.accounts.get(accountId);
      if (!account) {
        throw createHttpError(404, `Account '${accountId}' not found.`);
      }

      const prevStatus = account.status;
      account.status = nextStatus;
      account.updatedAt = new Date().toISOString();

      const auditEntry = this.appendAuditEntry({
        type: 'ACCOUNT_STATUS_CHANGE',
        actor: this.toActor(actorUser),
        fromAccountId: account.id,
        toAccountId: account.id,
        amount: 0,
        currency: account.currency,
        status: 'SUCCESS',
        note: `Account status changed from ${prevStatus} to ${nextStatus}${reason ? `: ${reason}` : ''}`,
        snapshot: {
          fromBalanceBefore: account.balance,
          fromBalanceAfter: account.balance,
          toBalanceBefore: account.balance,
          toBalanceAfter: account.balance
        }
      });

      this.persistToDisk();
      return { account, auditEntry };
    });
  }

  // ==========================================
  // SECURE MONEY MOVEMENT (OWNERSHIP + ATOMIC + ROLLBACK)
  // ==========================================

  async transferFunds({ fromAccountId, toAccountId, amount, note = '', idempotencyKey = null, actorUser }) {
    return this.acquireLock(async () => {
      const actor = this.toActor(actorUser);

      // Role check: AUDITOR is strictly read-only
      if (!actorUser || actorUser.role === 'AUDITOR') {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: fromAccountId || null,
          toAccountId: toAccountId || null,
          amount: Number(amount) || 0,
          status: 'REJECTED',
          reason: 'Permission denied: AUDITOR role has read-only access and cannot initiate transfers.',
          note
        });
        this.persistToDisk();
        throw createHttpError(403, 'Forbidden: Auditors have read-only access and cannot move funds.', { auditEntry });
      }

      if (idempotencyKey && this.processedIdempotencyKeys.has(idempotencyKey)) {
        throw createHttpError(409, `Duplicate transaction rejected: Idempotency key '${idempotencyKey}' was already processed.`);
      }

      const transferAmount = Number(amount);
      if (!Number.isFinite(transferAmount) || transferAmount <= 0) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: fromAccountId || null,
          toAccountId: toAccountId || null,
          amount: Number.isFinite(transferAmount) ? transferAmount : 0,
          status: 'REJECTED',
          reason: 'Transfer amount must be a positive finite number greater than zero.',
          note
        });
        this.persistToDisk();
        throw createHttpError(400, 'Transfer amount must be a positive number greater than zero.', { auditEntry });
      }

      const roundedAmount = Number(transferAmount.toFixed(2));

      if (!fromAccountId || !toAccountId) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: fromAccountId || null,
          toAccountId: toAccountId || null,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: 'Both sender (fromAccountId) and receiver (toAccountId) are required.',
          note
        });
        this.persistToDisk();
        throw createHttpError(400, 'Both sender and receiver accounts are required.', { auditEntry });
      }

      if (fromAccountId === toAccountId) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId,
          toAccountId,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: 'Cannot transfer funds to the same account.',
          note
        });
        this.persistToDisk();
        throw createHttpError(400, 'Sender and receiver account cannot be the same.', { auditEntry });
      }

      const sender = this.accounts.get(fromAccountId);
      const receiver = this.accounts.get(toAccountId);

      if (!sender) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId,
          toAccountId,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: `Sender account '${fromAccountId}' does not exist.`,
          note
        });
        this.persistToDisk();
        throw createHttpError(404, `Sender account '${fromAccountId}' not found.`, { auditEntry });
      }

      if (!receiver) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId,
          toAccountId,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: `Receiver account '${toAccountId}' does not exist.`,
          note
        });
        this.persistToDisk();
        throw createHttpError(404, `Receiver account '${toAccountId}' not found.`, { auditEntry });
      }

      // CRITICAL OWNERSHIP & SEGREGATION-OF-DUTIES CHECK:
      // Only the owner of the sender account can debit it (even ADMIN cannot drain another user's funds!).
      if (sender.ownerUserId !== actorUser.id) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: sender.id,
          toAccountId: receiver.id,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: `Unauthorized debit blocked: actor ${actorUser.id} (${actorUser.role}) does not own source account ${sender.id} (owner: ${sender.ownerUserId}).`,
          note,
          snapshot: {
            fromBalanceBefore: sender.balance,
            fromBalanceAfter: sender.balance,
            toBalanceBefore: receiver.balance,
            toBalanceAfter: receiver.balance
          }
        });
        this.persistToDisk();
        throw createHttpError(
          403,
          `Forbidden: You are not authorized to move funds out of account ${sender.id}. Attempt has been recorded in the audit ledger.`,
          { auditEntry }
        );
      }

      // Account status check (FROZEN accounts cannot send or receive)
      if (sender.status !== 'ACTIVE' || receiver.status !== 'ACTIVE') {
        const frozenId = sender.status !== 'ACTIVE' ? sender.id : receiver.id;
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: sender.id,
          toAccountId: receiver.id,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: `Account '${frozenId}' is FROZEN and cannot participate in transfers.`,
          note
        });
        this.persistToDisk();
        throw createHttpError(403, `Transfer blocked: account '${frozenId}' is currently FROZEN.`, { auditEntry });
      }

      // Overdraft prevention
      if (sender.balance < roundedAmount) {
        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: sender.id,
          toAccountId: receiver.id,
          amount: roundedAmount,
          status: 'REJECTED',
          reason: `Insufficient funds. Sender available balance: $${sender.balance.toFixed(2)}, attempted transfer: $${roundedAmount.toFixed(2)}.`,
          note,
          snapshot: {
            fromBalanceBefore: sender.balance,
            fromBalanceAfter: sender.balance,
            toBalanceBefore: receiver.balance,
            toBalanceAfter: receiver.balance
          }
        });
        this.persistToDisk();
        throw createHttpError(
          400,
          `Insufficient funds: account ${sender.id} has $${sender.balance.toFixed(2)}, required $${roundedAmount.toFixed(2)}.`,
          { auditEntry }
        );
      }

      // ATOMIC TRANSACTION EXECUTION WITH ROLLBACK ON FAILURE
      const originalSenderBalance = sender.balance;
      const originalReceiverBalance = receiver.balance;
      const originalSenderUpdated = sender.updatedAt;
      const originalReceiverUpdated = receiver.updatedAt;
      const now = new Date().toISOString();

      try {
        sender.balance = Number((sender.balance - roundedAmount).toFixed(2));
        sender.updatedAt = now;

        receiver.balance = Number((receiver.balance + roundedAmount).toFixed(2));
        receiver.updatedAt = now;

        if (sender.balance < 0) {
          throw new Error('Invariant violation: sender balance resulted in negative amount.');
        }

        const auditEntry = this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: sender.id,
          toAccountId: receiver.id,
          amount: roundedAmount,
          currency: sender.currency,
          status: 'SUCCESS',
          reason: null,
          note: String(note || '').trim(),
          timestamp: now,
          snapshot: {
            fromBalanceBefore: originalSenderBalance,
            fromBalanceAfter: sender.balance,
            toBalanceBefore: originalReceiverBalance,
            toBalanceAfter: receiver.balance
          }
        });

        this.persistToDisk();

        if (idempotencyKey) {
          this.processedIdempotencyKeys.add(idempotencyKey);
        }

        return {
          success: true,
          transaction: auditEntry,
          sender: { id: sender.id, name: sender.name, balance: sender.balance },
          receiver: { id: receiver.id, name: receiver.name, balance: receiver.balance }
        };
      } catch (atomicErr) {
        sender.balance = originalSenderBalance;
        sender.updatedAt = originalSenderUpdated;
        receiver.balance = originalReceiverBalance;
        receiver.updatedAt = originalReceiverUpdated;

        this.appendAuditEntry({
          type: 'TRANSFER',
          actor,
          fromAccountId: sender.id,
          toAccountId: receiver.id,
          amount: roundedAmount,
          currency: sender.currency,
          status: 'FAILED',
          reason: `Execution failure: ${atomicErr.message}. All balance changes rolled back.`,
          note: String(note || '').trim(),
          snapshot: {
            fromBalanceBefore: originalSenderBalance,
            fromBalanceAfter: originalSenderBalance,
            toBalanceBefore: originalReceiverBalance,
            toBalanceAfter: originalReceiverBalance
          }
        });

        this.persistToDisk();
        throw createHttpError(500, `Atomic transaction rolled back: ${atomicErr.message}`);
      }
    });
  }

  // Deposit capital (strictly ADMIN only!)
  async depositFunds({ accountId, amount, note = '', actorUser }) {
    return this.acquireLock(async () => {
      const actor = this.toActor(actorUser);
      if (!actorUser || actorUser.role !== 'ADMIN') {
        const auditEntry = this.appendAuditEntry({
          type: 'DEPOSIT',
          actor,
          toAccountId: accountId,
          amount: Number(amount) || 0,
          status: 'REJECTED',
          reason: `Permission denied: actor ${actor.userId} (${actor.role}) is not allowed to mint/deposit capital.`,
          note
        });
        this.persistToDisk();
        throw createHttpError(403, 'Forbidden: only ADMIN users can execute capital deposits.', { auditEntry });
      }

      const depositAmount = Number(amount);
      if (!Number.isFinite(depositAmount) || depositAmount <= 0) {
        throw createHttpError(400, 'Deposit amount must be a positive number greater than zero.');
      }

      const account = this.accounts.get(accountId);
      if (!account) {
        throw createHttpError(404, `Account '${accountId}' not found.`);
      }
      if (account.status !== 'ACTIVE') {
        throw createHttpError(403, `Deposit blocked: account '${accountId}' is currently FROZEN.`);
      }

      const rounded = Number(depositAmount.toFixed(2));
      const beforeBalance = account.balance;
      account.balance = Number((account.balance + rounded).toFixed(2));
      account.updatedAt = new Date().toISOString();

      const auditEntry = this.appendAuditEntry({
        type: 'DEPOSIT',
        actor,
        fromAccountId: null,
        toAccountId: account.id,
        amount: rounded,
        currency: account.currency,
        status: 'SUCCESS',
        note: note || 'Authorized admin capital deposit',
        snapshot: {
          fromBalanceBefore: null,
          fromBalanceAfter: null,
          toBalanceBefore: beforeBalance,
          toBalanceAfter: account.balance
        }
      });

      this.persistToDisk();
      return { account, auditEntry };
    });
  }

  // Withdraw funds (strictly Account Owner only, active account, sufficient balance)
  async withdrawFunds({ accountId, amount, note = '', actorUser }) {
    return this.acquireLock(async () => {
      const actor = this.toActor(actorUser);
      if (!actorUser || actorUser.role === 'AUDITOR') {
        const auditEntry = this.appendAuditEntry({
          type: 'WITHDRAWAL',
          actor,
          fromAccountId: accountId,
          amount: Number(amount) || 0,
          status: 'REJECTED',
          reason: 'Permission denied: AUDITOR role cannot withdraw funds.',
          note
        });
        this.persistToDisk();
        throw createHttpError(403, 'Forbidden: Auditors cannot withdraw funds.', { auditEntry });
      }

      const withdrawAmount = Number(amount);
      if (!Number.isFinite(withdrawAmount) || withdrawAmount <= 0) {
        throw createHttpError(400, 'Withdrawal amount must be a positive number greater than zero.');
      }

      const account = this.accounts.get(accountId);
      if (!account) {
        throw createHttpError(404, `Account '${accountId}' not found.`);
      }

      if (account.ownerUserId !== actorUser.id) {
        const auditEntry = this.appendAuditEntry({
          type: 'WITHDRAWAL',
          actor,
          fromAccountId: account.id,
          amount: Number(withdrawAmount.toFixed(2)),
          status: 'REJECTED',
          reason: `Unauthorized withdrawal blocked: actor ${actorUser.id} does not own account ${account.id}.`,
          note
        });
        this.persistToDisk();
        throw createHttpError(403, `Forbidden: you do not own account '${account.id}'.`, { auditEntry });
      }

      if (account.status !== 'ACTIVE') {
        throw createHttpError(403, `Withdrawal blocked: account '${account.id}' is currently FROZEN.`);
      }

      const rounded = Number(withdrawAmount.toFixed(2));
      if (account.balance < rounded) {
        const auditEntry = this.appendAuditEntry({
          type: 'WITHDRAWAL',
          actor,
          fromAccountId: account.id,
          toAccountId: null,
          amount: rounded,
          currency: account.currency,
          status: 'REJECTED',
          reason: `Insufficient funds for withdrawal. Balance: $${account.balance.toFixed(2)}, requested: $${rounded.toFixed(2)}`,
          note
        });
        this.persistToDisk();
        throw createHttpError(400, `Insufficient funds: balance is $${account.balance.toFixed(2)}, requested $${rounded.toFixed(2)}.`, { auditEntry });
      }

      const beforeBalance = account.balance;
      account.balance = Number((account.balance - rounded).toFixed(2));
      account.updatedAt = new Date().toISOString();

      const auditEntry = this.appendAuditEntry({
        type: 'WITHDRAWAL',
        actor,
        fromAccountId: account.id,
        toAccountId: null,
        amount: rounded,
        currency: account.currency,
        status: 'SUCCESS',
        note: note || 'Owner funds withdrawal',
        snapshot: {
          fromBalanceBefore: beforeBalance,
          fromBalanceAfter: account.balance,
          toBalanceBefore: null,
          toBalanceAfter: null
        }
      });

      this.persistToDisk();
      return { account, auditEntry };
    });
  }

  // Role-scoped audit trail query
  getAuditTrail({ type, status, accountId, search, limit = 100, offset = 0, requestUser = null } = {}) {
    let logs = [...this.auditLog];

    // If CUSTOMER, scope audit log strictly to accounts they own or attempts they initiated
    if (requestUser && requestUser.role === 'CUSTOMER') {
      const ownedIds = new Set(
        Array.from(this.accounts.values())
          .filter(a => a.ownerUserId === requestUser.id)
          .map(a => a.id)
      );
      logs = logs.filter(item =>
        ownedIds.has(item.fromAccountId) ||
        ownedIds.has(item.toAccountId) ||
        (item.actor && item.actor.userId === requestUser.id)
      );
    }

    if (type && type !== 'ALL') {
      logs = logs.filter(item => item.type === type.toUpperCase());
    }

    if (status && status !== 'ALL') {
      logs = logs.filter(item => item.status === status.toUpperCase());
    }

    if (accountId) {
      logs = logs.filter(item => item.fromAccountId === accountId || item.toAccountId === accountId);
    }

    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      logs = logs.filter(item =>
        item.transactionId.toLowerCase().includes(q) ||
        (item.note && item.note.toLowerCase().includes(q)) ||
        (item.reason && item.reason.toLowerCase().includes(q)) ||
        (item.fromAccountId && item.fromAccountId.toLowerCase().includes(q)) ||
        (item.toAccountId && item.toAccountId.toLowerCase().includes(q)) ||
        (item.actor && item.actor.email && item.actor.email.toLowerCase().includes(q)) ||
        (item.actor && item.actor.userId && item.actor.userId.toLowerCase().includes(q)) ||
        item.hash.toLowerCase().includes(q)
      );
    }

    logs.reverse();

    const total = logs.length;
    const paginated = logs.slice(Number(offset), Number(offset) + Number(limit));

    return {
      total,
      limit: Number(limit),
      offset: Number(offset),
      records: paginated
    };
  }

  verifyLedgerIntegrity() {
    if (this.auditLog.length === 0) {
      return {
        isValid: true,
        totalEntries: 0,
        message: 'Audit log is currently empty. Integrity is pristine.'
      };
    }

    for (let i = 0; i < this.auditLog.length; i++) {
      const entry = this.auditLog[i];

      if (entry.index !== i + 1) {
        return {
          isValid: false,
          compromisedIndex: entry.index,
          transactionId: entry.transactionId,
          reason: `Invalid entry sequence index: expected ${i + 1}, found ${entry.index}.`
        };
      }

      const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : this.auditLog[i - 1].hash;
      if (entry.previousHash !== expectedPrevHash) {
        return {
          isValid: false,
          compromisedIndex: entry.index,
          transactionId: entry.transactionId,
          reason: `Previous hash pointer mismatch at block ${entry.index}.`
        };
      }

      const computedHash = this.calculateHash(entry);
      if (entry.hash !== computedHash) {
        return {
          isValid: false,
          compromisedIndex: entry.index,
          transactionId: entry.transactionId,
          reason: `Cryptographic tamper detected at block ${entry.index}! Hash mismatch (tampered payload, amount, or actor).`
        };
      }
    }

    return {
      isValid: true,
      totalEntries: this.auditLog.length,
      latestHash: this.auditLog[this.auditLog.length - 1].hash,
      genesisHash: this.auditLog[0].hash,
      verifiedAt: new Date().toISOString(),
      message: `All ${this.auditLog.length} ledger blocks successfully validated. Cryptographic hash chain (including actor identity) is intact.`
    };
  }

  getStats(requestUser = null) {
    const visibleAccounts = requestUser
      ? this.getAccountsForUser(requestUser)
      : Array.from(this.accounts.values());

    const totalLiquidity = visibleAccounts.reduce((sum, acc) => sum + acc.balance, 0);
    const scopedAudit = this.getAuditTrail({ requestUser, limit: Number.MAX_SAFE_INTEGER }).records;

    const totalTransactions = scopedAudit.length;
    const successfulTransactions = scopedAudit.filter(t => t.status === 'SUCCESS').length;
    const failedTransactions = scopedAudit.filter(t => t.status === 'FAILED' || t.status === 'REJECTED').length;

    const integrity = this.verifyLedgerIntegrity();

    return {
      totalLiquidity: Number(totalLiquidity.toFixed(2)),
      currency: 'USD',
      activeAccountsCount: visibleAccounts.length,
      totalTransactions,
      successfulTransactions,
      failedTransactions,
      integrity
    };
  }
}

// Instantiate Ledger Engine
const ledger = new TransactionalLedger(process.env.LEDGER_FILE_PATH || DEFAULT_LEDGER_FILE);

// ==========================================
// SERVER-SIDE AUTH & RBAC MIDDLEWARE
// ==========================================

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required: missing Bearer token.' });
  }
  const token = authHeader.slice(7).trim();
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
  const user = ledger.findUserById(payload.sub);
  if (!user || !VALID_ROLES.includes(user.role)) {
    return res.status(401).json({ error: 'User session is no longer valid.' });
  }
  req.user = user;
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Forbidden: role '${req.user.role}' is not permitted to perform this action. Required: ${allowedRoles.join(' or ')}.`
      });
    }
    next();
  };
}

function handleRouteError(res, err) {
  const status = err.statusCode || 500;
  res.status(status).json({
    error: err.message || 'Internal server error',
    auditEntry: err.auditEntry || null
  });
}

// ==========================================
// PUBLIC ROUTES (HEALTH & AUTH)
// ==========================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    app: 'BalanceVault',
    version: SCHEMA_VERSION,
    authEnforced: true,
    timestamp: new Date().toISOString()
  });
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const result = ledger.authenticateUser(email, password);
    res.json(result);
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, initialDeposit } = req.body;
    const result = await ledger.registerCustomer({ name, email, password, initialDeposit });
    res.status(201).json({
      message: 'Customer registered and primary vault provisioned.',
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: ledger.sanitizeUser(req.user) });
});

// ==========================================
// PROTECTED RBAC API ROUTES
// ==========================================

app.get('/api/users', authenticate, requireRole('ADMIN'), (req, res) => {
  const users = Array.from(ledger.users.values()).map(u => ledger.sanitizeUser(u));
  res.json({ users });
});

app.get('/api/stats', authenticate, (req, res) => {
  try {
    res.json(ledger.getStats(req.user));
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Safe directory of destination accounts (without exposing other users' private balances)
app.get('/api/accounts/directory', authenticate, (req, res) => {
  try {
    res.json({ directory: ledger.getRecipientDirectory() });
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.get('/api/accounts', authenticate, (req, res) => {
  try {
    const { search } = req.query;
    const accounts = ledger.getAccountsForUser(req.user, search);
    res.json({ count: accounts.length, accounts });
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.get('/api/accounts/:id', authenticate, (req, res) => {
  try {
    const account = ledger.getAccountAuthorized(req.params.id, req.user);
    const history = ledger.getAuditTrail({ accountId: req.params.id, requestUser: req.user, limit: 50 });
    res.json({ account, recentHistory: history.records });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only ADMIN can provision new arbitrary accounts
app.post('/api/accounts', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { name, email, ownerUserId, initialBalance, currency } = req.body;
    const result = await ledger.createAccount({
      name,
      email,
      ownerUserId,
      initialBalance,
      currency,
      actorUser: req.user
    });
    res.status(201).json({
      message: 'Account created successfully',
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only ADMIN can freeze/unfreeze an account
app.patch('/api/accounts/:id/status', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { status, reason } = req.body;
    const result = await ledger.setAccountStatus({
      accountId: req.params.id,
      status,
      reason,
      actorUser: req.user
    });
    res.json({
      message: `Account ${req.params.id} updated to ${result.account.status}`,
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only ADMIN and CUSTOMER can attempt transfers; server enforces source account ownership!
app.post('/api/transfers', authenticate, requireRole('ADMIN', 'CUSTOMER'), async (req, res) => {
  try {
    const { fromAccountId, toAccountId, amount, note, idempotencyKey } = req.body;
    const key = idempotencyKey || req.headers['x-idempotency-key'];
    const result = await ledger.transferFunds({
      fromAccountId,
      toAccountId,
      amount,
      note,
      idempotencyKey: key,
      actorUser: req.user
    });
    res.status(200).json({
      message: 'Transfer completed successfully',
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only ADMIN can execute external capital deposits
app.post('/api/accounts/:id/deposit', authenticate, requireRole('ADMIN'), async (req, res) => {
  try {
    const { amount, note } = req.body;
    const result = await ledger.depositFunds({
      accountId: req.params.id,
      amount,
      note,
      actorUser: req.user
    });
    res.json({
      message: 'Deposit successful',
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only account owner (ADMIN or CUSTOMER) can withdraw from their own account
app.post('/api/accounts/:id/withdraw', authenticate, requireRole('ADMIN', 'CUSTOMER'), async (req, res) => {
  try {
    const { amount, note } = req.body;
    const result = await ledger.withdrawFunds({
      accountId: req.params.id,
      amount,
      note,
      actorUser: req.user
    });
    res.json({
      message: 'Withdrawal successful',
      ...result
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Role-scoped audit trail
app.get('/api/audit-trail', authenticate, (req, res) => {
  try {
    const { type, status, accountId, search, limit, offset } = req.query;
    const auditData = ledger.getAuditTrail({
      type,
      status,
      accountId,
      search,
      limit: limit ? parseInt(limit, 10) : 50,
      offset: offset ? parseInt(offset, 10) : 0,
      requestUser: req.user
    });
    res.json(auditData);
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.get('/api/audit-trail/:txId', authenticate, (req, res) => {
  try {
    const scoped = ledger.getAuditTrail({ requestUser: req.user, limit: Number.MAX_SAFE_INTEGER }).records;
    const tx = scoped.find(item => item.transactionId === req.params.txId);
    if (!tx) {
      return res.status(404).json({ error: `Transaction '${req.params.txId}' not found or access denied.` });
    }
    const computedHash = ledger.calculateHash(tx);
    res.json({
      transaction: tx,
      verification: {
        hashMatches: computedHash === tx.hash,
        recordedHash: tx.hash,
        computedHash
      }
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

app.get('/api/ledger/verify', authenticate, (req, res) => {
  try {
    res.json(ledger.verifyLedgerIntegrity());
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Only ADMIN can reset demo state
app.post('/api/demo/reset', authenticate, requireRole('ADMIN'), (req, res) => {
  try {
    ledger.seedInitialData();
    res.json({
      message: 'Ledger successfully re-initialized with RBAC demo accounts and audit records.',
      stats: ledger.getStats(req.user)
    });
  } catch (err) {
    handleRouteError(res, err);
  }
});

// Return 404 JSON for unknown /api routes rather than HTML
app.use('/api', (req, res) => {
  res.status(404).json({ error: `API endpoint '${req.originalUrl}' not found.` });
});

// Fallback route for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

let server = null;
if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`   BalanceVault v${SCHEMA_VERSION} - RBAC & Immutable Ledger`);
    console.log(`   Running locally on: http://localhost:${PORT}`);
    console.log(`   Data directory:     ${DATA_DIR}`);
    console.log(`=======================================================`);
  });
}

module.exports = { app, ledger, server };
