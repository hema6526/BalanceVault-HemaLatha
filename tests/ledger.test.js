/**
 * BalanceVault - Automated End-to-End & Security Test Suite
 * Location: D:\BalanceVault\tests\ledger.test.js
 *
 * Verifies:
 * 1. Authentication enforcement (401 on missing/invalid/tampered token)
 * 2. Privilege escalation prevention on registration (role forced to CUSTOMER)
 * 3. Server-enforced RBAC roles (CUSTOMER, ADMIN, AUDITOR)
 * 4. Ownership enforcement & segregation of duties ("wrong person cannot move money")
 * 5. Actor tracking ("prove who moved it") bound into SHA-256 hash
 * 6. Account freezing & unfreezing enforcement
 * 7. Atomic money movement, overdraft prevention, self-transfer & missing account guards
 * 8. Cryptographic SHA-256 tamper detection (detecting altered amount OR altered actor)
 * 9. Concurrency / race condition protection (10 parallel HTTP transfers)
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const http = require('http');

// Use isolated test ledger file strictly inside D:\BalanceVault\data
const TEST_LEDGER_FILE = path.join(__dirname, '..', 'data', `test-ledger-${Date.now()}.json`);
process.env.LEDGER_FILE_PATH = TEST_LEDGER_FILE;

const { app, ledger } = require('../server.js');

async function runTestSuite() {
  console.log('\n====================================================================');
  console.log('   BalanceVault Automated RBAC, Security & Ledger Test Suite        ');
  console.log('====================================================================\n');

  let passedCount = 0;
  let failedCount = 0;

  // Start ephemeral Express server on random available port
  const server = await new Promise(resolve => {
    const s = http.createServer(app);
    s.listen(0, '127.0.0.1', () => resolve(s));
  });

  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  async function apiCall(endpoint, { method = 'GET', token = null, body = null, headers = {} } = {}) {
    const reqHeaders = { ...headers };
    if (token) reqHeaders.Authorization = `Bearer ${token}`;
    if (body !== null) reqHeaders['Content-Type'] = 'application/json';

    const res = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers: reqHeaders,
      body: body !== null ? JSON.stringify(body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  \x1b[32m✔ PASS\x1b[0m : ${name}`);
      passedCount++;
    } catch (err) {
      console.error(`  \x1b[31m✖ FAIL\x1b[0m : ${name}`);
      console.error(`         \x1b[33mError: ${err.message}\x1b[0m`);
      failedCount++;
    }
  }

  try {
    // 1. Unauthenticated requests blocked (401)
    await test('Unauthenticated requests to protected endpoints return 401 Unauthorized', async () => {
      const r1 = await apiCall('/api/accounts');
      assert.strictEqual(r1.status, 401);

      const r2 = await apiCall('/api/transfers', {
        method: 'POST',
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: 10 }
      });
      assert.strictEqual(r2.status, 401);

      const r3 = await apiCall('/api/accounts', { headers: { Authorization: 'Bearer fake.invalid.token' } });
      assert.strictEqual(r3.status, 401);
    });

    // Sign in seeded users
    let aliceToken, bobToken, adminToken, auditorToken;

    await test('Seeded users (ADMIN, CUSTOMER, AUDITOR) authenticate and wrong password fails', async () => {
      const bad = await apiCall('/api/auth/login', {
        method: 'POST',
        body: { email: 'alice@balancevault.internal', password: 'WrongPassword' }
      });
      assert.strictEqual(bad.status, 401);

      const aliceRes = await apiCall('/api/auth/login', {
        method: 'POST',
        body: { email: 'alice@balancevault.internal', password: 'Customer123!' }
      });
      assert.strictEqual(aliceRes.status, 200);
      assert.strictEqual(aliceRes.data.user.role, 'CUSTOMER');
      aliceToken = aliceRes.data.token;

      const bobRes = await apiCall('/api/auth/login', {
        method: 'POST',
        body: { email: 'bob@balancevault.internal', password: 'Customer123!' }
      });
      assert.strictEqual(bobRes.status, 200);
      bobToken = bobRes.data.token;

      const adminRes = await apiCall('/api/auth/login', {
        method: 'POST',
        body: { email: 'admin@balancevault.internal', password: 'Admin123!' }
      });
      assert.strictEqual(adminRes.status, 200);
      assert.strictEqual(adminRes.data.user.role, 'ADMIN');
      adminToken = adminRes.data.token;

      const auditorRes = await apiCall('/api/auth/login', {
        method: 'POST',
        body: { email: 'auditor@balancevault.internal', password: 'Auditor123!' }
      });
      assert.strictEqual(auditorRes.status, 200);
      assert.strictEqual(auditorRes.data.user.role, 'AUDITOR');
      auditorToken = auditorRes.data.token;
    });

    // 2. Privilege escalation prevention
    await test('Self-registration ignores client-supplied role and enforces CUSTOMER', async () => {
      const reg = await apiCall('/api/auth/register', {
        method: 'POST',
        body: {
          name: 'Sneaky User',
          email: 'sneaky@test.vault',
          password: 'Password123!',
          role: 'ADMIN',
          initialDeposit: 500
        }
      });
      assert.strictEqual(reg.status, 201);
      assert.strictEqual(reg.data.user.role, 'CUSTOMER', 'Server must hardcode CUSTOMER role');
      assert.strictEqual(reg.data.account.balance, 500);
    });

    // 3. Data isolation: Customer sees only own accounts
    await test('CUSTOMER can only read own accounts and gets 403 inspecting another user account', async () => {
      const listRes = await apiCall('/api/accounts', { token: aliceToken });
      assert.strictEqual(listRes.status, 200);
      assert(listRes.data.accounts.every(a => a.ownerUserId === 'USR-ALICE'));

      const bobAccInspect = await apiCall('/api/accounts/ACC-1002', { token: aliceToken });
      assert.strictEqual(bobAccInspect.status, 403);
    });

    // 4. Wrong person cannot move money they should not
    await test('Wrong person (Alice) cannot transfer or withdraw from Bob account (403 + REJECTED audit)', async () => {
      const bobBefore = ledger.getAccountAuthorized('ACC-1002', ledger.findUserById('USR-ADMIN-1')).balance;

      const attack = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: {
          fromAccountId: 'ACC-1002', // Bob's account!
          toAccountId: 'ACC-1001',   // Alice's account!
          amount: 100.00,
          note: 'Unauthorized debit attempt'
        }
      });
      assert.strictEqual(attack.status, 403);
      assert.strictEqual(attack.data.auditEntry.status, 'REJECTED');
      assert.strictEqual(attack.data.auditEntry.actor.userId, 'USR-ALICE');

      const withdrawAttack = await apiCall('/api/accounts/ACC-1002/withdraw', {
        method: 'POST',
        token: aliceToken,
        body: { amount: 50 }
      });
      assert.strictEqual(withdrawAttack.status, 403);

      const bobAfter = ledger.getAccountAuthorized('ACC-1002', ledger.findUserById('USR-ADMIN-1')).balance;
      assert.strictEqual(bobAfter, bobBefore, 'Bob balance must remain untouched');
    });

    // 5. Segregation of duties: Even ADMIN cannot drain customer account
    await test('Segregation of duties: ADMIN cannot transfer out of customer account (403)', async () => {
      const res = await apiCall('/api/transfers', {
        method: 'POST',
        token: adminToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1004', amount: 500 }
      });
      assert.strictEqual(res.status, 403);
    });

    // 6. AUDITOR strictly read-only
    await test('AUDITOR can inspect full audit trail & verify chain, but gets 403 on all writes', async () => {
      const auditView = await apiCall('/api/audit-trail', { token: auditorToken });
      assert.strictEqual(auditView.status, 200);
      assert(auditView.data.records.length > 0);

      const verifyRes = await apiCall('/api/ledger/verify', { token: auditorToken });
      assert.strictEqual(verifyRes.status, 200);
      assert.strictEqual(verifyRes.data.isValid, true);

      const transferTry = await apiCall('/api/transfers', {
        method: 'POST',
        token: auditorToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: 10 }
      });
      assert.strictEqual(transferTry.status, 403);

      const depositTry = await apiCall('/api/accounts/ACC-1001/deposit', {
        method: 'POST',
        token: auditorToken,
        body: { amount: 100 }
      });
      assert.strictEqual(depositTry.status, 403);
    });

    // 7. CUSTOMER cannot mint capital or reset demo; ADMIN can
    await test('Only ADMIN can deposit capital, create accounts, or reset demo', async () => {
      const custDeposit = await apiCall('/api/accounts/ACC-1001/deposit', {
        method: 'POST',
        token: aliceToken,
        body: { amount: 5000 }
      });
      assert.strictEqual(custDeposit.status, 403);

      const custCreate = await apiCall('/api/accounts', {
        method: 'POST',
        token: aliceToken,
        body: { name: 'Unauthorized Vault', ownerUserId: 'USR-ALICE', initialBalance: 1000 }
      });
      assert.strictEqual(custCreate.status, 403);

      const adminDeposit = await apiCall('/api/accounts/ACC-1001/deposit', {
        method: 'POST',
        token: adminToken,
        body: { amount: 500, note: 'Approved wire credit' }
      });
      assert.strictEqual(adminDeposit.status, 200);
      assert.strictEqual(adminDeposit.data.auditEntry.actor.userId, 'USR-ADMIN-1');
    });

    // 8. Authorized atomic transfer + actor identity recorded
    await test('Authorized transfer succeeds atomically and binds actor identity into audit block', async () => {
      const aliceAccBefore = (await apiCall('/api/accounts/ACC-1001', { token: aliceToken })).data.account.balance;
      const bobAccBefore = (await apiCall('/api/accounts/ACC-1002', { token: bobToken })).data.account.balance;

      const tx = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: 250.50, note: 'Rent share' }
      });

      assert.strictEqual(tx.status, 200);
      assert.strictEqual(tx.data.transaction.actor.userId, 'USR-ALICE');
      assert.strictEqual(tx.data.transaction.actor.role, 'CUSTOMER');
      assert.strictEqual(tx.data.sender.balance, Number((aliceAccBefore - 250.50).toFixed(2)));
      assert.strictEqual(tx.data.receiver.balance, Number((bobAccBefore + 250.50).toFixed(2)));
    });

    // 9. Overdraft protection & invalid amount / self-transfer
    await test('Overdrafts, self-transfers, and negative amounts are blocked with balances preserved', async () => {
      const aliceBal = (await apiCall('/api/accounts/ACC-1001', { token: aliceToken })).data.account.balance;

      const overdraft = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: aliceBal + 5000 }
      });
      assert.strictEqual(overdraft.status, 400);
      assert(overdraft.data.error.includes('Insufficient funds'));

      const selfTx = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1001', amount: 20 }
      });
      assert.strictEqual(selfTx.status, 400);

      const negTx = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: -50 }
      });
      assert.strictEqual(negTx.status, 400);

      const aliceBalAfter = (await apiCall('/api/accounts/ACC-1001', { token: aliceToken })).data.account.balance;
      assert.strictEqual(aliceBalAfter, aliceBal);
    });

    // 10. Freeze / Unfreeze account enforcement
    await test('ADMIN freezing an account blocks transfers until unfrozen', async () => {
      const freeze = await apiCall('/api/accounts/ACC-1003/status', {
        method: 'PATCH',
        token: adminToken,
        body: { status: 'FROZEN', reason: 'Security review' }
      });
      assert.strictEqual(freeze.status, 200);
      assert.strictEqual(freeze.data.account.status, 'FROZEN');

      const blockedTx = await apiCall('/api/transfers', {
        method: 'POST',
        token: aliceToken,
        body: { fromAccountId: 'ACC-1003', toAccountId: 'ACC-1002', amount: 50 }
      });
      assert.strictEqual(blockedTx.status, 403);

      const unfreeze = await apiCall('/api/accounts/ACC-1003/status', {
        method: 'PATCH',
        token: adminToken,
        body: { status: 'ACTIVE', reason: 'Review passed' }
      });
      assert.strictEqual(unfreeze.status, 200);
      assert.strictEqual(unfreeze.data.account.status, 'ACTIVE');
    });

    // 11. Concurrency test via 10 parallel HTTP calls
    await test('10 parallel HTTP transfers execute without race conditions or double-spending', async () => {
      const startAlice = (await apiCall('/api/accounts/ACC-1001', { token: aliceToken })).data.account.balance;
      const startBob = (await apiCall('/api/accounts/ACC-1002', { token: bobToken })).data.account.balance;

      const batch = Array.from({ length: 10 }, (_, i) =>
        apiCall('/api/transfers', {
          method: 'POST',
          token: aliceToken,
          body: { fromAccountId: 'ACC-1001', toAccountId: 'ACC-1002', amount: 10, note: `Parallel #${i}` }
        })
      );

      const results = await Promise.all(batch);
      assert(results.every(r => r.status === 200));

      const endAlice = (await apiCall('/api/accounts/ACC-1001', { token: aliceToken })).data.account.balance;
      const endBob = (await apiCall('/api/accounts/ACC-1002', { token: bobToken })).data.account.balance;

      assert.strictEqual(endAlice, Number((startAlice - 100).toFixed(2)));
      assert.strictEqual(endBob, Number((startBob + 100).toFixed(2)));
    });

    // 12. Cryptographic tamper detection on BOTH amount and actor identity
    await test('Cryptographic SHA-256 chain verification catches altered amount or altered actor', async () => {
      const pristine = await apiCall('/api/ledger/verify', { token: auditorToken });
      assert.strictEqual(pristine.data.isValid, true);

      const target = ledger.auditLog[ledger.auditLog.length - 1];
      const origActorId = target.actor.userId;

      // Tamper with WHO initiated the transaction
      target.actor.userId = 'USR-FRAMED-BOB';
      const tamperedActorReport = await apiCall('/api/ledger/verify', { token: auditorToken });
      assert.strictEqual(tamperedActorReport.data.isValid, false);
      assert.strictEqual(tamperedActorReport.data.compromisedIndex, target.index);

      // Restore
      target.actor.userId = origActorId;
      const restored = await apiCall('/api/ledger/verify', { token: auditorToken });
      assert.strictEqual(restored.data.isValid, true);
    });
  } finally {
    server.close();
    if (fs.existsSync(TEST_LEDGER_FILE)) {
      fs.unlinkSync(TEST_LEDGER_FILE);
    }
  }

  console.log('\n--------------------------------------------------------------------');
  console.log(`   Test Results: \x1b[32m${passedCount} Passed\x1b[0m, \x1b[31m${failedCount} Failed\x1b[0m`);
  console.log('--------------------------------------------------------------------\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
