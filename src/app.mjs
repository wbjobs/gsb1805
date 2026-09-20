// 演示 UI 逻辑：鉴权、笔记 CRUD、轮换密码、迁移进度与异常提示。
import { VaultClient } from './vault-client.mjs';

const $ = (sel) => document.querySelector(sel);

const els = {
  backendBadge: $('#backendBadge'),
  authView: $('#authView'), authTitle: $('#authTitle'), authHint: $('#authHint'),
  password: $('#password'), passwordConfirm: $('#passwordConfirm'), confirmField: $('#confirmField'),
  btnAuth: $('#btnAuth'),
  notesView: $('#notesView'), noteInput: $('#noteInput'), btnAdd: $('#btnAdd'),
  noteList: $('#noteList'), emptyHint: $('#emptyHint'), activeKidLabel: $('#activeKidLabel'),
  btnRotate: $('#btnRotate'), btnBench: $('#btnBench'), btnLock: $('#btnLock'),
  banner: $('#migrationBanner'), migrationTitle: $('#migrationTitle'),
  migrationStats: $('#migrationStats'), migrationBar: $('#migrationBar'),
  migrationDetail: $('#migrationDetail'), btnPause: $('#btnPause'), btnResume: $('#btnResume'),
  rotateDialog: $('#rotateDialog'), oldPwd: $('#oldPwd'), newPwd: $('#newPwd'),
  newPwd2: $('#newPwd2'), btnDoRotate: $('#btnDoRotate'),
  toastHost: $('#toastHost'),
};

let client = null;
let mode = 'unlock'; // 'unlock' | 'create'
let busy = false;

function toast(message, kind = 'info', ms = 3600) {
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.textContent = message;
  els.toastHost.appendChild(node);
  setTimeout(() => node.remove(), ms);
}

// 统一的错误码 -> 中文提示，覆盖密钥派生、密码错误、存储、迁移等异常。
function friendlyError(err) {
  const map = {
    BAD_PASSWORD: '密码错误，或加密数据已损坏',
    BAD_NEW_PASSWORD: '新密码无效',
    NOT_INITIALIZED: '保险库尚未初始化',
    ALREADY_INITIALIZED: '保险库已初始化，请直接解锁',
    LOCKED: '保险库已锁定，请先解锁',
    NO_WEBCRYPTO: '当前浏览器不支持 Web Crypto，请使用现代浏览器并通过 HTTPS/localhost 访问',
    NO_INDEXEDDB: '当前浏览器不支持 IndexedDB，无法本地存储',
    IDB_BLOCKED: '数据库被其它标签页占用，请关闭旧标签页后重试',
    KDF_FAILED: '密钥派生失败，请重试',
    ENCRYPT_FAILED: '加密失败，请重试',
    DECRYPT_FAILED: '解密失败：数据可能已损坏',
    UNWRAP_FAILED: '解封密钥失败：密码错误或数据损坏',
    WRAP_FAILED: '包装密钥失败，请重试',
    ROTATION_BUSY: '已有轮换任务在进行，请等待其暂停或完成',
    TARGET_MISMATCH: '迁移目标与当前密钥不一致，请重新轮换',
    UNKNOWN_KID: '数据引用了不存在的密钥版本（旧密钥可能已被清理）',
  };
  return map[err?.code] || err?.message || '发生未知错误，请重试';
}

function guard(fn) {
  return async (...args) => {
    if (busy) return;
    busy = true;
    try { return await fn(...args); }
    catch (err) { toast(friendlyError(err), 'error', 5000); console.error(err); }
    finally { busy = false; }
  };
}

function setBusgOn(btn, on, text) {
  if (!btn) return;
  btn.disabled = on;
  if (text) btn.dataset.busyText = text;
  if (on && text) { btn._origText = btn.textContent; btn.textContent = text; }
  else if (!on && btn._origText) { btn.textContent = btn._origText; }
}

async function boot() {
  try {
    client = await VaultClient.create();
  } catch (err) {
    toast(friendlyError(err), 'error', 6000);
    return;
  }
  els.backendBadge.hidden = false;
  els.backendBadge.textContent = client.isWorkerBackend ? '后台线程：Web Worker' : '降级：主线程模式';
  bindMigrationEvents();

  const initialized = await client.isInitialized();
  mode = initialized ? 'unlock' : 'create';
  renderAuth();
}

function renderAuth() {
  els.authView.hidden = false;
  els.notesView.hidden = true;
  for (const id of ['btnRotate', 'btnBench', 'btnLock']) els[id].hidden = true;
  els.confirmField.hidden = mode === 'unlock';
  els.authTitle.textContent = mode === 'create' ? '创建保险库' : '解锁保险库';
  els.authHint.textContent = mode === 'create'
    ? '首次使用，请设置主密码。忘记密码将无法找回数据（本地端到端加密）。'
    : '输入主密码。密钥派生在 Web Worker 中完成，不会卡住页面。';
  els.btnAuth.textContent = mode === 'create' ? '创建并进入' : '解锁';
  els.password.focus();
}

els.btnAuth.addEventListener('click', guard(async () => {
  const pwd = els.password.value;
  if (!pwd) return toast('请输入密码', 'error');
  setBusgOn(els.btnAuth, true, '请稍候…');
  try {
    if (mode === 'create') {
      if (pwd !== els.passwordConfirm.value) return toast('两次输入的密码不一致', 'error');
      await client.initialize(pwd);
      toast('保险库创建成功', 'success');
    } else {
      await client.unlock(pwd);
      toast('解锁成功', 'success');
    }
    els.password.value = '';
    els.passwordConfirm.value = '';
    await enterApp();
  } finally {
    setBusgOn(els.btnAuth, false);
  }
}));

els.password.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') els.btnAuth.click();
});

async function enterApp() {
  els.authView.hidden = true;
  els.notesView.hidden = false;
  for (const id of ['btnRotate', 'btnBench', 'btnLock']) els[id].hidden = false;
  els.activeKidLabel.textContent = `活动密钥 ${shortKid(await safeActiveKid())}`;
  await loadNotes();
  const state = await client.migrationState();
  if (state) {
    toast('检测到上次未完成的迁移，正在自动续迁…', 'info');
    client.resumeMigration().catch((err) => toast(friendlyError(err), 'error'));
  }
}

async function safeActiveKid() {
  try { return await client.getActiveKid(); } catch { return '—'; }
}

function shortKid(kid) {
  return kid ? String(kid).slice(-10) : '—';
}

async function loadNotes() {
  const notes = await client.listNotes();
  const activeKid = await safeActiveKid();
  els.noteList.innerHTML = '';
  els.emptyHint.hidden = notes.length > 0;
  for (const note of notes) els.noteList.appendChild(renderNote(note, activeKid));
}

function renderNote(note, activeKid) {
  const li = document.createElement('li');
  li.className = 'note-item';
  li.dataset.id = note.id;
  li.innerHTML = `
    <div class="note-text"></div>
    <div class="note-meta">
      <span>${new Date(note.updatedAt).toLocaleString()}</span>
      <span class="kid-label"></span>
      <span class="spacer"></span>
      <span class="note-actions">
        <button class="btn tiny ghost act-edit">编辑</button>
        <button class="btn tiny ghost act-del">删除</button>
      </span>
    </div>`;
  li.querySelector('.note-text').textContent = note.content;
  // listNotes 不回传 kid，这里不显示旧/新标签；编辑保存会自动升级到活动密钥。
  li.querySelector('.kid-label').textContent = '';
  li.querySelector('.act-del').addEventListener('click', guard(async () => {
    if (!confirm('确定删除这条笔记？')) return;
    await client.deleteNote(note.id);
    li.remove();
    els.emptyHint.hidden = els.noteList.children.length > 0;
  }));
  li.querySelector('.act-edit').addEventListener('click', () => enterEdit(li, note));
  return li;
}

function enterEdit(li, note) {
  if (li.classList.contains('editing')) return;
  li.classList.add('editing');
  const textDiv = li.querySelector('.note-text');
  const ta = document.createElement('textarea');
  ta.rows = 3;
  ta.value = note.content;
  li.insertBefore(ta, textDiv);
  textDiv.hidden = true;
  const actions = li.querySelector('.note-actions');
  const save = document.createElement('button');
  save.className = 'btn tiny primary act-save';
  save.textContent = '保存';
  const cancel = document.createElement('button');
  cancel.className = 'btn tiny ghost act-cancel';
  cancel.textContent = '取消';
  actions.prepend(save);
  actions.prepend(cancel);
  cancel.addEventListener('click', () => li.replaceWith(renderNote(note)));
  save.addEventListener('click', guard(async () => {
    await client.updateNote(note.id, ta.value);
    toast('已保存（并用当前密钥重新加密）', 'success');
    await loadNotes();
  }));
}

els.btnAdd.addEventListener('click', guard(async () => {
  const content = els.noteInput.value.trim();
  if (!content) return;
  await client.addNote(content);
  els.noteInput.value = '';
  await loadNotes();
}));
els.noteInput.addEventListener('keydown', (ev) => {
  if ((ev.metaKey || ev.ctrlKey) && ev.key === 'Enter') els.btnAdd.click();
});

els.btnLock.addEventListener('click', () => {
  client.lock();
  mode = 'unlock';
  renderAuth();
  els.banner.hidden = true;
});

// ---- 轮换密码 ----
els.btnRotate.addEventListener('click', () => {
  els.oldPwd.value = els.newPwd.value = els.newPwd2.value = '';
  els.rotateDialog.showModal();
});

els.btnDoRotate.addEventListener('click', guard(async (ev) => {
  ev.preventDefault();
  const oldPwd = els.oldPwd.value;
  const p1 = els.newPwd.value;
  const p2 = els.newPwd2.value;
  if (!p1 || p1 !== p2) return toast('两次输入的新密码不一致', 'error');
  if (!oldPwd) return toast('请输入当前密码', 'error');
  if (p1 === oldPwd) return toast('新密码不能与旧密码相同', 'error');
  setBusgOn(els.btnDoRotate, true, '派生新密钥中…');
  try {
    showBanner('密钥轮换中：正在重新包装密钥版本…', true);
    await client.rotatePassword(oldPwd, p1, { batchSize: 20, batchDelayMs: 4 });
    els.activeKidLabel.textContent = `活动密钥 ${shortKid(await safeActiveKid())}`;
    toast('密码已轮换，旧笔记可直接用新密码打开', 'success', 5000);
    els.rotateDialog.close('confirm');
    await loadNotes();
  } finally {
    setBusgOn(els.btnDoRotate, false);
  }
}));

// ---- 迁移进度 ----
let totalCount = 0;
let migratedTotal = 0;

function showBanner(title, indeterminate) {
  els.banner.hidden = false;
  els.migrationTitle.textContent = title;
  els.btnPause.hidden = false;
  els.btnResume.hidden = true;
  els.migrationBar.removeAttribute('value');
  if (!indeterminate) els.migrationBar.value = 0;
}

function bindMigrationEvents() {
  client.on('rotated', () => showBanner('正在用新密钥后台迁移笔记…', true));
  client.on('migration:progress', (p) => {
    els.banner.hidden = false;
    migratedTotal = p.migratedTotal;
    totalCount = migratedTotal + p.remaining;
    const pct = totalCount === 0 ? 100 : Math.round((migratedTotal / totalCount) * 100);
    els.migrationBar.value = pct;
    els.migrationBar.max = 100;
    els.migrationTitle.textContent = '密钥迁移进行中…';
    els.migrationStats.textContent = `已迁移 ${migratedTotal} / ${totalCount}（${pct}%）`;
    els.migrationDetail.textContent = '分批处理，每批结束已保存进度；关闭页面后可自动续迁。';
  });
  client.on('migration:paused', ({ state }) => {
    els.btnPause.hidden = true;
    els.btnResume.hidden = false;
    els.migrationTitle.textContent = '迁移已暂停（进度已保存）';
    els.migrationStats.textContent = `已迁移 ${state?.migratedCount ?? 0} 条，失败 ${state?.failedCount ?? 0} 条`;
    els.migrationDetail.textContent = '点击“继续”恢复，或刷新页面后解锁时自动续迁。';
  });
  client.on('migration:blocked', ({ remaining }) => {
    els.btnPause.hidden = true;
    els.btnResume.hidden = false;
    els.migrationTitle.textContent = '部分笔记迁移失败';
    els.migrationStats.textContent = `剩余 ${remaining} 条`;
    els.migrationDetail.textContent = '这些笔记仍可用旧数据密钥打开；修复后点“继续”重试。';
    toast(`有 ${remaining} 条笔记迁移失败，未删除旧密钥以保证可读`, 'error', 6000);
  });
  client.on('migration:done', () => {
    els.banner.hidden = true;
    toast('全部笔记已迁移到新密钥，旧密钥版本已清理', 'success');
    loadNotes();
  });
  client.on('migration:itemerror', ({ id, error }) => {
    toast(`笔记迁移失败：${String(error).slice(0, 60)}`, 'error', 5000);
  });
  client.on('migration:error', (err) => toast(friendlyError(err), 'error', 5000));
}

els.btnPause.addEventListener('click', () => {
  client.pauseMigration();
  toast('将在当前批次结束后暂停…', 'info');
});
els.btnResume.addEventListener('click', guard(async () => {
  els.btnPause.hidden = false;
  els.btnResume.hidden = true;
  await client.resumeMigration();
}));

// ---- 性能基准：批量插入 200 条并做一次轮换迁移，给出耗时 ----
els.btnBench.addEventListener('click', guard(async () => {
  const n = 200;
  setBusgOn(els.btnBench, true, `写入 ${n} 条…`);
  const t0 = performance.now();
  for (let i = 0; i < n; i += 1) {
    // 逐条写入，模拟真实交互；加解密在 Worker 内并行排队
    await client.addNote(`benchmark note #${i} — ${'机密内容。'.repeat(20)}`);
  }
  const tWrite = performance.now() - t0;
  setBusgOn(els.btnBench, true, '轮换 + 迁移中…');
  const benchPwd = `bench-${Date.now()}`;
  const t1 = performance.now();
  await client.rotatePassword(benchPwd, benchPwd + '-new', { batchSize: 50, batchDelayMs: 0, concurrency: 8 });
  const tRotate = performance.now() - t1;
  await loadNotes();
  toast(
    `写入 ${n} 条 ${tWrite.toFixed(0)}ms；轮换+迁移 ${tRotate.toFixed(0)}ms` +
    `（含 1 次 PBKDF2 派生）`,
    'success', 8000,
  );
}));

boot().catch((err) => toast(friendlyError(err), 'error', 6000));
