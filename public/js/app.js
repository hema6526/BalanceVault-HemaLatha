/**
 * BalanceVault - Client Application Controller
 * Communicates strictly with server-enforced RBAC Express API (/api/*)
 *
 * Location: D:\BalanceVault\public\js\app.js
 */

(function () {
  'use strict';

  const TOKEN_KEY = 'bv_auth_token';

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || null,
    user: null,
    accounts: [],
    directory: [],
    users: [],
    auditTrail: [],
    activeTypeFilter: 'ALL',
    activeStatusFilter: 'ALL',
    searchQuery: '',
    stats: null
  };

  const els = {
    // Auth Screen
    authScreen: document.getElementById('authScreen'),
    dashboardApp: document.getElementById('dashboardApp'),
    tabLoginBtn: document.getElementById('tabLoginBtn'),
    tabRegisterBtn: document.getElementById('tabRegisterBtn'),
    loginForm: document.getElementById('loginForm'),
    registerForm: document.getElementById('registerForm'),
    loginEmail: document.getElementById('loginEmail'),
    loginPassword: document.getElementById('loginPassword'),

    // Header / Session
    currentUserRoleBadge: document.getElementById('currentUserRoleBadge'),
    currentUserName: document.getElementById('currentUserName'),
    currentUserEmail: document.getElementById('currentUserEmail'),
    btnLogout: document.getElementById('btnLogout'),
    rbacBanner: document.getElementById('rbacBanner'),

    // Top stats
    statLiquidityLabel: document.getElementById('statLiquidityLabel'),
    statTotalLiquidity: document.getElementById('statTotalLiquidity'),
    statActiveAccounts: document.getElementById('statActiveAccounts'),
    statTotalTransactions: document.getElementById('statTotalTransactions'),
    statSuccessCount: document.getElementById('statSuccessCount'),
    statFailedCount: document.getElementById('statFailedCount'),
    statLedgerIntegrity: document.getElementById('statLedgerIntegrity'),
    statChainBlocks: document.getElementById('statChainBlocks'),
    ledgerStatusPill: document.getElementById('ledgerStatusPill'),
    ledgerStatusText: document.getElementById('ledgerStatusText'),
    btnRunAudit: document.getElementById('btnRunAudit'),
    btnOpenNewAccountModal: document.getElementById('btnOpenNewAccountModal'),

    // Transfer form
    transferCardSection: document.getElementById('transferCardSection'),
    transferForm: document.getElementById('transferForm'),
    fromAccountSelect: document.getElementById('fromAccountSelect'),
    toAccountSelect: document.getElementById('toAccountSelect'),
    transferAmount: document.getElementById('transferAmount'),
    transferNote: document.getElementById('transferNote'),
    senderBalanceHint: document.getElementById('senderBalanceHint'),
    receiverBalanceHint: document.getElementById('receiverBalanceHint'),
    maxTransferHint: document.getElementById('maxTransferHint'),
    btnTransferMax: document.getElementById('btnTransferMax'),
    transferPreview: document.getElementById('transferPreview'),
    previewSenderAfter: document.getElementById('previewSenderAfter'),
    btnExecuteTransfer: document.getElementById('btnExecuteTransfer'),

    // Accounts section
    accountsSectionTitle: document.getElementById('accountsSectionTitle'),
    accountsList: document.getElementById('accountsList'),
    accountSearchInput: document.getElementById('accountSearchInput'),
    btnRefreshAccounts: document.getElementById('btnRefreshAccounts'),

    // Ledger section
    ledgerTableBody: document.getElementById('ledgerTableBody'),
    ledgerSearchInput: document.getElementById('ledgerSearchInput'),
    ledgerShowingText: document.getElementById('ledgerShowingText'),
    btnExportLedgerJson: document.getElementById('btnExportLedgerJson'),
    btnResetDemoData: document.getElementById('btnResetDemoData'),
    tabButtons: document.querySelectorAll('.tab-btn'),

    // Modals
    newAccountModal: document.getElementById('newAccountModal'),
    newAccountForm: document.getElementById('newAccountForm'),
    accOwnerSelect: document.getElementById('accOwnerSelect'),
    depositModal: document.getElementById('depositModal'),
    depositForm: document.getElementById('depositForm'),
    depositAccountId: document.getElementById('depositAccountId'),
    depositAccountInfo: document.getElementById('depositAccountInfo'),
    depositAmount: document.getElementById('depositAmount'),
    depositNote: document.getElementById('depositNote'),
    withdrawModal: document.getElementById('withdrawModal'),
    withdrawForm: document.getElementById('withdrawForm'),
    withdrawAccountId: document.getElementById('withdrawAccountId'),
    withdrawAccountInfo: document.getElementById('withdrawAccountInfo'),
    withdrawAmount: document.getElementById('withdrawAmount'),
    withdrawMaxNote: document.getElementById('withdrawMaxNote'),
    withdrawNote: document.getElementById('withdrawNote'),
    auditReportModal: document.getElementById('auditReportModal'),
    auditReportLoading: document.getElementById('auditReportLoading'),
    auditReportResult: document.getElementById('auditReportResult'),
    btnReVerifyModal: document.getElementById('btnReVerifyModal'),
    blockDetailModal: document.getElementById('blockDetailModal'),
    blockDetailContent: document.getElementById('blockDetailContent'),

    toastContainer: document.getElementById('toastContainer')
  };

  // =========================================================
  // UTILITIES
  // =========================================================

  function formatCurrency(val) {
    const num = Number(val) || 0;
    return '$' + num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function formatShortDate(isoString) {
    if (!isoString) return '--';
    return new Date(isoString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(title, message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
    } else if (type === 'error') {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
    } else {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    }

    toast.innerHTML = `
      <div class="toast-icon">${iconSvg}</div>
      <div class="toast-body">
        <div class="toast-title">${escapeHtml(title)}</div>
        <div class="toast-msg">${escapeHtml(message)}</div>
      </div>
    `;

    els.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(50px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to Clipboard', text, 'info');
    }).catch(() => {
      showToast('Copy Failed', 'Unable to access clipboard.', 'warning');
    });
  }

  // =========================================================
  // SERVER API CLIENT (STRICTLY SERVER-ENFORCED)
  // =========================================================

  async function requestJson(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (state.token) {
      headers.Authorization = `Bearer ${state.token}`;
    }
    if (options.body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, { ...options, headers });
    const data = await res.json().catch(() => ({}));

    if (res.status === 401 && url !== '/api/auth/login') {
      logout(false);
      throw new Error(data.error || 'Session expired. Please sign in again.');
    }

    if (!res.ok) {
      const err = new Error(data.error || `Request failed (${res.status})`);
      err.status = res.status;
      err.auditEntry = data.auditEntry || null;
      throw err;
    }

    return data;
  }

  const api = {
    login: (email, password) =>
      requestJson('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

    register: (payload) =>
      requestJson('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) }),

    me: () => requestJson('/api/auth/me'),
    getUsers: () => requestJson('/api/users'),
    getStats: () => requestJson('/api/stats'),
    getDirectory: () => requestJson('/api/accounts/directory'),

    getAccounts: (search = '') => {
      const url = search ? `/api/accounts?search=${encodeURIComponent(search)}` : '/api/accounts';
      return requestJson(url);
    },

    createAccount: (data) =>
      requestJson('/api/accounts', { method: 'POST', body: JSON.stringify(data) }),

    setAccountStatus: (accountId, status, reason = '') =>
      requestJson(`/api/accounts/${accountId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status, reason })
      }),

    transferFunds: (payload) =>
      requestJson('/api/transfers', {
        method: 'POST',
        headers: {
          'X-Idempotency-Key': 'key_' + Date.now() + '_' + Math.random().toString(36).slice(2, 10)
        },
        body: JSON.stringify(payload)
      }),

    deposit: (accountId, payload) =>
      requestJson(`/api/accounts/${accountId}/deposit`, { method: 'POST', body: JSON.stringify(payload) }),

    withdraw: (accountId, payload) =>
      requestJson(`/api/accounts/${accountId}/withdraw`, { method: 'POST', body: JSON.stringify(payload) }),

    getAuditTrail: (params = {}) => {
      const query = new URLSearchParams();
      if (params.type && params.type !== 'ALL') query.set('type', params.type);
      if (params.status && params.status !== 'ALL') query.set('status', params.status);
      if (params.accountId) query.set('accountId', params.accountId);
      if (params.search) query.set('search', params.search);
      query.set('limit', '100');
      return requestJson(`/api/audit-trail?${query.toString()}`);
    },

    verifyLedger: () => requestJson('/api/ledger/verify'),
    resetDemo: () => requestJson('/api/demo/reset', { method: 'POST' })
  };

  // =========================================================
  // AUTH & SESSION UI
  // =========================================================

  function setSession(token, user) {
    state.token = token;
    state.user = user;
    sessionStorage.setItem(TOKEN_KEY, token);
    showDashboard();
  }

  function logout(notify = true) {
    state.token = null;
    state.user = null;
    state.accounts = [];
    state.directory = [];
    state.auditTrail = [];
    sessionStorage.removeItem(TOKEN_KEY);
    els.dashboardApp.style.display = 'none';
    els.authScreen.style.display = 'flex';
    if (notify) {
      showToast('Signed Out', 'You have signed out cleanly.', 'info');
    }
  }

  function applyRoleUiState() {
    const user = state.user;
    if (!user) return;

    els.currentUserName.textContent = user.name;
    els.currentUserEmail.textContent = user.email;
    els.currentUserRoleBadge.textContent = user.role;
    els.currentUserRoleBadge.className = `role-pill role-${user.role.toLowerCase()}`;

    const isAdmin = user.role === 'ADMIN';
    const isAuditor = user.role === 'AUDITOR';

    els.btnOpenNewAccountModal.style.display = isAdmin ? 'inline-flex' : 'none';
    els.btnResetDemoData.style.display = isAdmin ? 'inline-flex' : 'none';
    els.transferCardSection.style.display = isAuditor ? 'none' : 'block';

    if (isAdmin) {
      els.accountsSectionTitle.textContent = 'All System Accounts';
      els.statLiquidityLabel.textContent = 'Total Vault Liquidity';
      els.rbacBanner.innerHTML = `
        <span><strong>ADMIN Session:</strong> You can provision accounts, deposit capital, freeze/unfreeze accounts, and transfer from your own account (<code>USR-ADMIN-1</code>). Segregation-of-duties blocks debiting customer-owned accounts.</span>
      `;
    } else if (isAuditor) {
      els.accountsSectionTitle.textContent = 'All System Accounts (Read-Only)';
      els.statLiquidityLabel.textContent = 'Total Vault Liquidity';
      els.rbacBanner.innerHTML = `
        <span><strong>AUDITOR Session (Read-Only):</strong> You can inspect all balances, audit history, and SHA-256 verification proofs. All money movement endpoints return <code>403 Forbidden</code> for this role.</span>
      `;
    } else {
      els.accountsSectionTitle.textContent = 'Your Owned Accounts';
      els.statLiquidityLabel.textContent = 'Your Total Balance';
      els.rbacBanner.innerHTML = `
        <span><strong>CUSTOMER Session:</strong> You can view balances and move money <strong>only from accounts you own</strong>, and inspect audit trails involving your accounts. Transfers to other users use the safe recipient directory.</span>
      `;
    }
  }

  function showDashboard() {
    els.authScreen.style.display = 'none';
    els.dashboardApp.style.display = 'flex';
    applyRoleUiState();
    refreshAll();
  }

  // =========================================================
  // RENDER FUNCTIONS
  // =========================================================

  function renderStats(stats) {
    if (!stats) return;
    state.stats = stats;

    els.statTotalLiquidity.textContent = formatCurrency(stats.totalLiquidity);
    els.statActiveAccounts.textContent = stats.activeAccountsCount;
    els.statTotalTransactions.textContent = stats.totalTransactions;
    els.statSuccessCount.textContent = `${stats.successfulTransactions} Success`;
    els.statFailedCount.textContent = `${stats.failedTransactions} Rejected/Failed`;

    if (stats.integrity && stats.integrity.isValid) {
      els.statLedgerIntegrity.textContent = 'SECURE';
      els.statLedgerIntegrity.className = 'stat-value integrity-pristine';
      els.statChainBlocks.textContent = `${stats.integrity.totalEntries} blocks verified`;
      els.ledgerStatusText.textContent = 'Ledger Verified (SHA-256)';
      els.ledgerStatusPill.className = 'status-pill status-verified';
    } else {
      els.statLedgerIntegrity.textContent = 'TAMPERED';
      els.statLedgerIntegrity.className = 'stat-value text-danger';
      els.statChainBlocks.textContent = 'Block integrity compromised!';
      els.ledgerStatusText.textContent = 'Integrity Compromised!';
      els.ledgerStatusPill.className = 'status-pill text-danger';
    }
  }

  function renderAccounts(accounts, directory) {
    state.accounts = accounts;
    state.directory = directory;

    const currentUserId = state.user ? state.user.id : null;
    const isAdmin = state.user && state.user.role === 'ADMIN';
    const isAuditor = state.user && state.user.role === 'AUDITOR';

    // Owned active accounts for the Sender dropdown
    const ownedAccounts = accounts.filter(acc => acc.ownerUserId === currentUserId);

    const currentFrom = els.fromAccountSelect.value;
    const currentTo = els.toAccountSelect.value;

    els.fromAccountSelect.innerHTML = '<option value="">-- Choose Your Source Account --</option>';
    ownedAccounts.forEach(acc => {
      const optFrom = document.createElement('option');
      optFrom.value = acc.id;
      const statusSuffix = acc.status !== 'ACTIVE' ? ' [FROZEN]' : '';
      optFrom.textContent = `${acc.name} (${acc.id}) - ${formatCurrency(acc.balance)}${statusSuffix}`;
      els.fromAccountSelect.appendChild(optFrom);
    });

    els.toAccountSelect.innerHTML = '<option value="">-- Choose Destination Account --</option>';
    directory.forEach(item => {
      const optTo = document.createElement('option');
      optTo.value = item.id;
      const statusSuffix = item.status !== 'ACTIVE' ? ' [FROZEN]' : '';
      optTo.textContent = `${item.name} (${item.id}) — Owner: ${item.ownerName}${statusSuffix}`;
      els.toAccountSelect.appendChild(optTo);
    });

    if (currentFrom && ownedAccounts.some(a => a.id === currentFrom)) {
      els.fromAccountSelect.value = currentFrom;
    }
    if (currentTo && directory.some(a => a.id === currentTo)) {
      els.toAccountSelect.value = currentTo;
    }

    updateTransferFormHints();

    if (accounts.length === 0) {
      els.accountsList.innerHTML = `
        <div class="loading-state">
          <span>No accessible accounts found for your role.</span>
        </div>
      `;
      return;
    }

    els.accountsList.innerHTML = accounts.map(acc => {
      const isOwner = acc.ownerUserId === currentUserId;
      const isFrozen = acc.status !== 'ACTIVE';
      const frozenBadge = isFrozen ? `<span class="account-frozen-badge">FROZEN</span>` : '';

      const actionButtons = [];
      if (!isAuditor && isOwner && !isFrozen) {
        actionButtons.push(`<button class="btn btn-secondary btn-sm" onclick="window.BalanceVault.selectSender('${escapeHtml(acc.id)}')">Transfer</button>`);
        actionButtons.push(`<button class="btn btn-secondary btn-sm" onclick="window.BalanceVault.openWithdrawModal('${escapeHtml(acc.id)}')">- Withdraw</button>`);
      }
      if (isAdmin && !isFrozen) {
        actionButtons.push(`<button class="btn btn-secondary btn-sm" onclick="window.BalanceVault.openDepositModal('${escapeHtml(acc.id)}')">+ Deposit</button>`);
      }
      if (isAdmin) {
        const nextStatus = isFrozen ? 'ACTIVE' : 'FROZEN';
        const btnLabel = isFrozen ? 'Unfreeze' : 'Freeze';
        actionButtons.push(`<button class="btn btn-ghost btn-sm ${isFrozen ? 'text-success' : 'text-danger'}" onclick="window.BalanceVault.toggleFreeze('${escapeHtml(acc.id)}', '${nextStatus}')">${btnLabel}</button>`);
      }
      actionButtons.push(`<button class="btn btn-ghost btn-sm" onclick="window.BalanceVault.filterByAccount('${escapeHtml(acc.id)}')">Logs</button>`);

      return `
        <div class="account-item" data-account-id="${escapeHtml(acc.id)}">
          <div class="account-top">
            <div>
              <span class="account-id-badge" onclick="window.BalanceVault.copyText('${escapeHtml(acc.id)}')">
                ${escapeHtml(acc.id)}
              </span>
              ${frozenBadge}
              <div class="account-name">${escapeHtml(acc.name)}</div>
              <div class="account-email">Owner: ${escapeHtml(acc.ownerName || acc.ownerUserId)} (${escapeHtml(acc.email)})</div>
            </div>
            <div class="account-balance-group">
              <div class="account-balance-label">Balance</div>
              <div class="account-balance-val">${formatCurrency(acc.balance)}</div>
            </div>
          </div>
          <div class="account-actions">${actionButtons.join('')}</div>
        </div>
      `;
    }).join('');
  }

  function renderAuditTrail(data) {
    state.auditTrail = data.records || [];
    els.ledgerShowingText.textContent = `Showing ${state.auditTrail.length} of ${data.total || state.auditTrail.length} audited events`;

    if (state.auditTrail.length === 0) {
      els.ledgerTableBody.innerHTML = `
        <tr>
          <td colspan="10" class="text-center py-8 text-muted">
            No audit records match the selected filter.
          </td>
        </tr>
      `;
      return;
    }

    els.ledgerTableBody.innerHTML = state.auditTrail.map(tx => {
      let statusBadge = '';
      if (tx.status === 'SUCCESS') {
        statusBadge = `<span class="status-badge status-badge-success">● SUCCESS</span>`;
      } else if (tx.status === 'FAILED') {
        statusBadge = `<span class="status-badge status-badge-failed" title="${escapeHtml(tx.reason || '')}">✖ FAILED</span>`;
      } else {
        statusBadge = `<span class="status-badge status-badge-rejected" title="${escapeHtml(tx.reason || '')}">⚠ REJECTED</span>`;
      }

      let typeBadge = '';
      if (tx.type === 'TRANSFER') {
        typeBadge = `<span class="badge-type type-transfer">TRANSFER</span>`;
      } else if (tx.type === 'DEPOSIT') {
        typeBadge = `<span class="badge-type type-deposit">DEPOSIT</span>`;
      } else if (tx.type === 'WITHDRAWAL') {
        typeBadge = `<span class="badge-type type-withdrawal">WITHDRAW</span>`;
      } else if (tx.type === 'ACCOUNT_STATUS_CHANGE') {
        typeBadge = `<span class="badge-type type-withdrawal">STATUS</span>`;
      } else {
        typeBadge = `<span class="badge-type type-creation">PROVISION</span>`;
      }

      const actor = tx.actor || { userId: 'SYSTEM', email: 'system', role: 'SYSTEM' };
      const roleClass = ['ADMIN', 'CUSTOMER', 'AUDITOR'].includes(actor.role)
        ? `role-${actor.role.toLowerCase()}`
        : 'role-admin';
      const actorHtml = `
        <div class="actor-cell">
          <span class="actor-id">${escapeHtml(actor.userId)}</span>
          <span class="role-pill ${roleClass}">${escapeHtml(actor.role)}</span>
        </div>
      `;

      let movementHtml = '';
      if (tx.type === 'TRANSFER') {
        movementHtml = `
          <div class="movement-cell">
            <span class="acc-pill" onclick="window.BalanceVault.filterByAccount('${escapeHtml(tx.fromAccountId)}')">${escapeHtml(tx.fromAccountId)}</span>
            <span class="movement-arrow">&rarr;</span>
            <span class="acc-pill" onclick="window.BalanceVault.filterByAccount('${escapeHtml(tx.toAccountId)}')">${escapeHtml(tx.toAccountId)}</span>
          </div>
          ${tx.note ? `<span class="movement-note" title="${escapeHtml(tx.note)}">${escapeHtml(tx.note)}</span>` : ''}
          ${tx.reason ? `<span class="movement-note text-danger" title="${escapeHtml(tx.reason)}">${escapeHtml(tx.reason)}</span>` : ''}
        `;
      } else if (tx.type === 'DEPOSIT' || tx.type === 'ACCOUNT_CREATION') {
        movementHtml = `
          <div class="movement-cell">
            <span class="text-muted">External / Init</span>
            <span class="movement-arrow">&rarr;</span>
            <span class="acc-pill" onclick="window.BalanceVault.filterByAccount('${escapeHtml(tx.toAccountId)}')">${escapeHtml(tx.toAccountId)}</span>
          </div>
          ${tx.note ? `<span class="movement-note">${escapeHtml(tx.note)}</span>` : ''}
          ${tx.reason ? `<span class="movement-note text-danger">${escapeHtml(tx.reason)}</span>` : ''}
        `;
      } else if (tx.type === 'WITHDRAWAL') {
        movementHtml = `
          <div class="movement-cell">
            <span class="acc-pill" onclick="window.BalanceVault.filterByAccount('${escapeHtml(tx.fromAccountId)}')">${escapeHtml(tx.fromAccountId)}</span>
            <span class="movement-arrow">&rarr;</span>
            <span class="text-muted">External Outflow</span>
          </div>
          ${tx.note ? `<span class="movement-note">${escapeHtml(tx.note)}</span>` : ''}
          ${tx.reason ? `<span class="movement-note text-danger">${escapeHtml(tx.reason)}</span>` : ''}
        `;
      } else {
        movementHtml = `
          <div class="movement-cell">
            <span class="acc-pill" onclick="window.BalanceVault.filterByAccount('${escapeHtml(tx.toAccountId)}')">${escapeHtml(tx.toAccountId)}</span>
          </div>
          ${tx.note ? `<span class="movement-note">${escapeHtml(tx.note)}</span>` : ''}
        `;
      }

      let amountClass = 'amount-neutral';
      let amountSign = '';
      if (tx.status === 'SUCCESS') {
        if (tx.type === 'TRANSFER' || tx.type === 'DEPOSIT') {
          amountClass = 'amount-credit';
          amountSign = '+';
        } else if (tx.type === 'WITHDRAWAL') {
          amountClass = 'amount-debit';
          amountSign = '-';
        }
      } else {
        amountClass = 'text-muted';
      }

      const shortHash = tx.hash ? tx.hash.substring(0, 8) + '...' + tx.hash.substring(58) : 'GENESIS';

      return `
        <tr>
          <td class="block-index">#${tx.index}</td>
          <td class="tx-time">${formatShortDate(tx.timestamp)}</td>
          <td>
            <span class="tx-id-badge" onclick="window.BalanceVault.copyText('${escapeHtml(tx.transactionId)}')">
              ${escapeHtml(tx.transactionId)}
            </span>
          </td>
          <td>${actorHtml}</td>
          <td>${typeBadge}</td>
          <td>${movementHtml}</td>
          <td class="text-right">
            <span class="amount-val ${amountClass}">${amountSign}${formatCurrency(tx.amount)}</span>
          </td>
          <td>${statusBadge}</td>
          <td>
            <span class="hash-snippet" title="Full SHA-256: ${escapeHtml(tx.hash)}" onclick="window.BalanceVault.inspectBlock(${tx.index})">
              ${escapeHtml(shortHash)}
            </span>
          </td>
          <td>
            <button class="btn btn-ghost btn-sm" onclick="window.BalanceVault.inspectBlock(${tx.index})" title="Inspect block proof">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function updateTransferFormHints() {
    const fromId = els.fromAccountSelect.value;
    const toId = els.toAccountSelect.value;
    const amountVal = parseFloat(els.transferAmount.value) || 0;

    const sender = state.accounts.find(a => a.id === fromId);
    const receiver = state.directory.find(a => a.id === toId);

    Array.from(els.toAccountSelect.options).forEach(opt => {
      opt.disabled = Boolean(opt.value && opt.value === fromId);
    });

    if (sender) {
      els.senderBalanceHint.textContent = `Avail: ${formatCurrency(sender.balance)}`;
      els.maxTransferHint.textContent = `Max: ${formatCurrency(sender.balance)}`;
    } else {
      els.senderBalanceHint.textContent = 'Select an owned account';
      els.maxTransferHint.textContent = 'Available: $0.00';
    }

    if (receiver) {
      els.receiverBalanceHint.textContent = `Recipient: ${receiver.ownerName}`;
    } else {
      els.receiverBalanceHint.textContent = 'Select destination';
    }

    if (sender && receiver && amountVal > 0) {
      els.transferPreview.style.display = 'block';
      const senderNewBal = sender.balance - amountVal;
      els.previewSenderAfter.textContent = formatCurrency(senderNewBal);

      if (senderNewBal < 0) {
        els.previewSenderAfter.className = 'text-danger';
        els.senderBalanceHint.className = 'label-info text-danger';
        els.senderBalanceHint.textContent = `OVERDRAFT BLOCKED (Short: ${formatCurrency(Math.abs(senderNewBal))})`;
      } else {
        els.previewSenderAfter.className = '';
        els.senderBalanceHint.className = 'label-info';
      }
    } else {
      els.transferPreview.style.display = 'none';
    }
  }

  // =========================================================
  // DATA REFRESH & CONTROLLERS
  // =========================================================

  async function refreshAll() {
    if (!state.token) return;
    try {
      const promises = [
        api.getStats(),
        api.getAccounts(els.accountSearchInput.value),
        api.getDirectory(),
        api.getAuditTrail({
          type: state.activeTypeFilter,
          status: state.activeStatusFilter,
          search: state.searchQuery
        })
      ];

      if (state.user && state.user.role === 'ADMIN') {
        promises.push(api.getUsers());
      }

      const [stats, accountsData, dirData, auditData, usersData] = await Promise.all(promises);

      if (usersData && Array.isArray(usersData.users)) {
        state.users = usersData.users;
        populateOwnerDropdown();
      }

      renderStats(stats);
      renderAccounts(accountsData.accounts, dirData.directory || []);
      renderAuditTrail(auditData);
    } catch (err) {
      showToast('Server Error', err.message, 'error');
    }
  }

  function populateOwnerDropdown() {
    if (!els.accOwnerSelect) return;
    els.accOwnerSelect.innerHTML = '';
    state.users.forEach(u => {
      const opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = `${u.name} (${u.role}) - ${u.email}`;
      els.accOwnerSelect.appendChild(opt);
    });
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    try {
      const result = await api.login(els.loginEmail.value.trim(), els.loginPassword.value);
      showToast('Signed In', `Welcome ${result.user.name} (${result.user.role})`, 'success');
      setSession(result.token, result.user);
    } catch (err) {
      showToast('Login Failed', err.message, 'error');
    }
  }

  async function handleRegisterSubmit(e) {
    e.preventDefault();
    try {
      const name = document.getElementById('regName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPassword').value;
      const initialDeposit = parseFloat(document.getElementById('regDeposit').value) || 0;
      const result = await api.register({ name, email, password, initialDeposit });
      showToast('Registration Complete', `Account ${result.account.id} provisioned for ${result.user.name}.`, 'success');
      setSession(result.token, result.user);
    } catch (err) {
      showToast('Registration Failed', err.message, 'error');
    }
  }

  async function handleTransferSubmit(e) {
    e.preventDefault();
    const fromAccountId = els.fromAccountSelect.value;
    const toAccountId = els.toAccountSelect.value;
    const amount = parseFloat(els.transferAmount.value);
    const note = els.transferNote.value;

    if (!fromAccountId || !toAccountId) {
      showToast('Validation Error', 'Please select both sender and receiver accounts.', 'warning');
      return;
    }

    els.btnExecuteTransfer.disabled = true;
    els.btnExecuteTransfer.innerHTML = `<div class="spinner" style="width: 16px; height: 16px; border-width: 2px;"></div> Verifying Ownership & Transferring...`;

    try {
      const result = await api.transferFunds({ fromAccountId, toAccountId, amount, note });
      showToast('Transfer Succeeded', `Transferred ${formatCurrency(amount)} to ${toAccountId}. Block #${result.transaction.index} committed.`, 'success');
      els.transferAmount.value = '';
      els.transferNote.value = '';
      els.transferPreview.style.display = 'none';
      await refreshAll();
    } catch (err) {
      showToast('Server Blocked / Rejected Transfer', err.message, 'error');
      await refreshAll();
    } finally {
      els.btnExecuteTransfer.disabled = false;
      els.btnExecuteTransfer.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="22" y1="2" x2="11" y2="13"></line>
          <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
        </svg>
        Execute Atomic Transfer
      `;
    }
  }

  async function handleNewAccountSubmit(e) {
    e.preventDefault();
    const ownerUserId = els.accOwnerSelect.value;
    const name = document.getElementById('accHolderName').value.trim();
    const initialBalance = parseFloat(document.getElementById('accInitialBalance').value) || 0;

    try {
      const result = await api.createAccount({ ownerUserId, name, initialBalance });
      showToast('Account Provisioned', `Created ${result.account.id} for owner ${ownerUserId}.`, 'success');
      closeAllModals();
      els.newAccountForm.reset();
      await refreshAll();
    } catch (err) {
      showToast('Creation Failed', err.message, 'error');
    }
  }

  async function handleDepositSubmit(e) {
    e.preventDefault();
    const accountId = els.depositAccountId.value;
    const amount = parseFloat(els.depositAmount.value);
    const note = els.depositNote.value;

    try {
      const result = await api.deposit(accountId, { amount, note });
      showToast('Deposit Complete', `Credited ${formatCurrency(amount)} to ${accountId}. New balance: ${formatCurrency(result.account.balance)}`, 'success');
      closeAllModals();
      els.depositForm.reset();
      await refreshAll();
    } catch (err) {
      showToast('Deposit Blocked', err.message, 'error');
    }
  }

  async function handleWithdrawSubmit(e) {
    e.preventDefault();
    const accountId = els.withdrawAccountId.value;
    const amount = parseFloat(els.withdrawAmount.value);
    const note = els.withdrawNote.value;

    try {
      const result = await api.withdraw(accountId, { amount, note });
      showToast('Withdrawal Complete', `Debited ${formatCurrency(amount)} from ${accountId}. Remaining: ${formatCurrency(result.account.balance)}`, 'success');
      closeAllModals();
      els.withdrawForm.reset();
      await refreshAll();
    } catch (err) {
      showToast('Withdrawal Blocked', err.message, 'error');
      await refreshAll();
    }
  }

  async function runCryptographicVerification() {
    els.auditReportModal.classList.add('open');
    els.auditReportLoading.style.display = 'block';
    els.auditReportResult.style.display = 'none';

    try {
      const result = await api.verifyLedger();
      els.auditReportLoading.style.display = 'none';
      els.auditReportResult.style.display = 'block';

      const banner = document.getElementById('auditBanner');
      const bannerTitle = document.getElementById('auditBannerTitle');
      const bannerDesc = document.getElementById('auditBannerDesc');
      const bannerIcon = document.getElementById('auditBannerIcon');

      document.getElementById('auditTotalBlocks').textContent = result.totalEntries;
      document.getElementById('auditVerifiedTime').textContent = formatShortDate(result.verifiedAt || new Date().toISOString());
      document.getElementById('auditLatestHash').textContent = result.latestHash || '0'.repeat(64);

      if (result.isValid) {
        banner.className = 'audit-status-banner';
        bannerIcon.innerHTML = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
        bannerTitle.textContent = 'Integrity Verified: Cryptographically Pristine';
        bannerDesc.textContent = result.message;
        document.getElementById('auditTamperStatus').textContent = '0 Alterations Found';
        document.getElementById('auditTamperStatus').className = 'text-success';
      } else {
        banner.className = 'audit-status-banner error';
        bannerIcon.innerHTML = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
        bannerTitle.textContent = 'TAMPER DETECTED: Hash Chain Broken';
        bannerDesc.textContent = result.reason || 'Cryptographic discrepancy detected.';
        document.getElementById('auditTamperStatus').textContent = `Compromised at Block #${result.compromisedIndex}`;
        document.getElementById('auditTamperStatus').className = 'text-danger';
      }
    } catch (err) {
      els.auditReportLoading.innerHTML = `<div class="text-danger">Failed to verify ledger: ${escapeHtml(err.message)}</div>`;
    }
  }

  function inspectBlock(blockIndex) {
    const block = state.auditTrail.find(b => b.index === blockIndex);
    if (!block) return;

    const actor = block.actor || { userId: 'SYSTEM', email: 'system', role: 'SYSTEM' };

    els.blockDetailModal.classList.add('open');
    document.getElementById('blockModalSubtitle').textContent = `Inspecting Block #${block.index} (${block.transactionId})`;

    els.blockDetailContent.innerHTML = `
      <div class="audit-details-grid mb-4">
        <div class="audit-stat-item">
          <span class="text-muted">Transaction ID</span>
          <strong class="font-mono">${escapeHtml(block.transactionId)}</strong>
        </div>
        <div class="audit-stat-item">
          <span class="text-muted">Initiated By (Verified Actor)</span>
          <strong>${escapeHtml(actor.userId)} (${escapeHtml(actor.role)}) — ${escapeHtml(actor.email)}</strong>
        </div>
        <div class="audit-stat-item">
          <span class="text-muted">Recorded Timestamp</span>
          <strong>${new Date(block.timestamp).toISOString()}</strong>
        </div>
        <div class="audit-stat-item">
          <span class="text-muted">Execution Status</span>
          <strong class="${block.status === 'SUCCESS' ? 'text-success' : 'text-danger'}">${escapeHtml(block.status)}</strong>
        </div>
      </div>

      <div class="hash-explorer-box mt-4">
        <div class="hash-line">
          <span class="hash-label">Previous Block Hash:</span>
          <code class="hash-code">${escapeHtml(block.previousHash)}</code>
        </div>
        <div class="hash-line mt-3">
          <span class="hash-label">Current Block SHA-256 Hash (Covers Payload + Actor Identity):</span>
          <code class="hash-code">${escapeHtml(block.hash)}</code>
        </div>
      </div>

      <div class="mt-4">
        <span class="hash-label mb-2" style="display:block;">Raw Block Canonical JSON Payload:</span>
        <pre class="hash-code" style="max-height: 220px; overflow-y: auto;">${escapeHtml(JSON.stringify(block, null, 2))}</pre>
      </div>
    `;
  }

  function closeAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('open'));
  }

  // =========================================================
  // GLOBAL EXPORTS
  // =========================================================

  window.BalanceVault = {
    copyText: (t) => copyToClipboard(t),
    selectSender: (accId) => {
      els.fromAccountSelect.value = accId;
      updateTransferFormHints();
      els.fromAccountSelect.scrollIntoView({ behavior: 'smooth' });
    },
    filterByAccount: (accId) => {
      els.ledgerSearchInput.value = accId;
      state.searchQuery = accId;
      refreshAll();
    },
    openDepositModal: (accId) => {
      const acc = state.accounts.find(a => a.id === accId);
      if (!acc) return;
      els.depositAccountId.value = acc.id;
      els.depositAccountInfo.innerHTML = `Account: <strong>${escapeHtml(acc.name)} (${acc.id})</strong> &bull; Balance: <strong>${formatCurrency(acc.balance)}</strong>`;
      els.depositAmount.value = '';
      els.depositNote.value = '';
      els.depositModal.classList.add('open');
    },
    openWithdrawModal: (accId) => {
      const acc = state.accounts.find(a => a.id === accId);
      if (!acc) return;
      els.withdrawAccountId.value = acc.id;
      els.withdrawAccountInfo.innerHTML = `Account: <strong>${escapeHtml(acc.name)} (${acc.id})</strong>`;
      els.withdrawMaxNote.textContent = `Available for withdrawal: ${formatCurrency(acc.balance)}`;
      els.withdrawAmount.value = '';
      els.withdrawAmount.max = acc.balance;
      els.withdrawNote.value = '';
      els.withdrawModal.classList.add('open');
    },
    toggleFreeze: async (accId, nextStatus) => {
      try {
        await api.setAccountStatus(accId, nextStatus, `Admin toggled account to ${nextStatus}`);
        showToast('Account Status Updated', `Account ${accId} is now ${nextStatus}.`, 'success');
        await refreshAll();
      } catch (err) {
        showToast('Action Failed', err.message, 'error');
      }
    },
    inspectBlock: (index) => inspectBlock(index)
  };

  // =========================================================
  // EVENT LISTENERS & INIT
  // =========================================================

  function initEventListeners() {
    // Auth Tabs & Forms
    els.tabLoginBtn.addEventListener('click', () => {
      els.tabLoginBtn.classList.add('active');
      els.tabRegisterBtn.classList.remove('active');
      els.loginForm.style.display = 'block';
      els.registerForm.style.display = 'none';
    });

    els.tabRegisterBtn.addEventListener('click', () => {
      els.tabRegisterBtn.classList.add('active');
      els.tabLoginBtn.classList.remove('active');
      els.registerForm.style.display = 'block';
      els.loginForm.style.display = 'none';
    });

    els.loginForm.addEventListener('submit', handleLoginSubmit);
    els.registerForm.addEventListener('submit', handleRegisterSubmit);
    els.btnLogout.addEventListener('click', () => logout(true));

    // One-click Demo Sign-In Buttons
    document.querySelectorAll('.demo-role-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const email = btn.getAttribute('data-email');
        const pass = btn.getAttribute('data-pass');
        els.loginEmail.value = email;
        els.loginPassword.value = pass;
        try {
          const result = await api.login(email, pass);
          showToast('Signed In', `Active Role: ${result.user.role} (${result.user.name})`, 'success');
          setSession(result.token, result.user);
        } catch (err) {
          showToast('Demo Sign-In Failed', err.message, 'error');
        }
      });
    });

    // Dashboard controls
    els.fromAccountSelect.addEventListener('change', updateTransferFormHints);
    els.toAccountSelect.addEventListener('change', updateTransferFormHints);
    els.transferAmount.addEventListener('input', updateTransferFormHints);
    els.transferForm.addEventListener('submit', handleTransferSubmit);

    document.querySelectorAll('.btn-chip[data-amount]').forEach(btn => {
      btn.addEventListener('click', () => {
        const addAmount = parseFloat(btn.getAttribute('data-amount')) || 0;
        const current = parseFloat(els.transferAmount.value) || 0;
        els.transferAmount.value = (current + addAmount).toFixed(2);
        updateTransferFormHints();
      });
    });

    els.btnTransferMax.addEventListener('click', () => {
      const fromId = els.fromAccountSelect.value;
      const sender = state.accounts.find(a => a.id === fromId);
      if (sender && sender.balance > 0) {
        els.transferAmount.value = sender.balance.toFixed(2);
        updateTransferFormHints();
      } else {
        showToast('No Sender Selected', 'Select an owned account with positive balance first.', 'warning');
      }
    });

    els.btnOpenNewAccountModal.addEventListener('click', () => {
      els.newAccountForm.reset();
      populateOwnerDropdown();
      els.newAccountModal.classList.add('open');
    });

    els.btnRunAudit.addEventListener('click', runCryptographicVerification);
    els.ledgerStatusPill.addEventListener('click', runCryptographicVerification);
    els.btnReVerifyModal.addEventListener('click', runCryptographicVerification);

    document.querySelectorAll('[data-close-modal]').forEach(btn => {
      btn.addEventListener('click', closeAllModals);
    });

    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closeAllModals();
      });
    });

    els.newAccountForm.addEventListener('submit', handleNewAccountSubmit);
    els.depositForm.addEventListener('submit', handleDepositSubmit);
    els.withdrawForm.addEventListener('submit', handleWithdrawSubmit);

    els.tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        els.tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const type = btn.getAttribute('data-type');
        const status = btn.getAttribute('data-status');
        if (status) {
          state.activeStatusFilter = status;
          state.activeTypeFilter = 'ALL';
        } else if (type) {
          state.activeTypeFilter = type;
          state.activeStatusFilter = 'ALL';
        }
        refreshAll();
      });
    });

    let searchDebounceTimer;
    els.ledgerSearchInput.addEventListener('input', (e) => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        state.searchQuery = e.target.value.trim();
        refreshAll();
      }, 250);
    });

    let accSearchTimer;
    els.accountSearchInput.addEventListener('input', () => {
      clearTimeout(accSearchTimer);
      accSearchTimer = setTimeout(() => refreshAll(), 250);
    });

    els.btnRefreshAccounts.addEventListener('click', () => {
      showToast('Refreshing', 'Synchronizing with server...', 'info');
      refreshAll();
    });

    els.btnExportLedgerJson.addEventListener('click', () => {
      if (!state.auditTrail || state.auditTrail.length === 0) {
        showToast('Ledger Empty', 'No ledger records available to export.', 'warning');
        return;
      }
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(state.auditTrail, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `balancevault-audit-trail-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showToast('Export Started', 'Audit ledger exported as JSON.', 'success');
    });

    els.btnResetDemoData.addEventListener('click', async () => {
      if (confirm('Reset ledger to initial RBAC demonstration state?')) {
        try {
          await api.resetDemo();
          showToast('Demo Reset', 'Vault ledger reset to seed state.', 'success');
          await refreshAll();
        } catch (err) {
          showToast('Reset Failed', err.message, 'error');
        }
      }
    });

    setInterval(() => {
      if (state.token) refreshAll();
    }, 15000);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    initEventListeners();
    if (state.token) {
      try {
        const res = await api.me();
        state.user = res.user;
        showDashboard();
      } catch {
        logout(false);
      }
    }
  });
})();
