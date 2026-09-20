// UI 装配：解锁/初始化、笔记增删查、密钥轮换、迁移进度、异常 toast。
import { NoteStore } from './db.js';
import { CryptoClient } from './crypto-client.js';
import { KeyManager } from './key-manager.js';

const $ = (id) => document.getElementById(id);

function toast(message, kind = 'info', ms = 4000) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function showError(err) {
  console.error(err);
  toast(err?.message || String(err), 'error', 6000);
}

const store = await new NoteStore().open();
const crypto = new CryptoClient('./src/crypto-worker.js');

let total = 0;
const km = new KeyManager({
  store,
  crypto,
  batchSize: 100,
  onEvent: (e) => {
    switch (e.type) {
      case 'migration-start':
        $('progress-wrap').style.display = 'block';
        $('btn-rotate').disabled = true;
        toast(`开始迁移：v${e.from} → v${e.to}`, 'info');
        break;
      case 'migration-progress': {
        const pct = total ? Math.min(100, (e.processed / total) * 100) : 0;
        $('progress-bar').style.width = pct + '%';
        $('progress-text').textContent =
          `已迁移 ${e.processed}/${total} 条` + (e.failed ? `，失败 ${e.failed} 条` : '');
        break;
      }
      case 'migration-done':
        $('progress-wrap').style.display = 'none';
        $('btn-rotate').disabled = false;
        toast(`迁移完成：v${e.from} → v${e.to}，共 ${e.processed} 条，旧密钥已销毁`, 'success');
        refresh();
        break;
      case 'migration-paused':
        $('btn-rotate').disabled = false;
        toast(`迁移已暂停（${e.processed} 条），刷新或重启后会自动续跑`, 'info');
        break;
      case 'migration-error':
        $('btn-rotate').disabled = false;
        if (e.failed) {
          toast(`迁移完成但有 ${e.failed.length} 条数据损坏（ID: ${e.failed.join(', ')}），` +
            `旧密钥已保留，修复后重新轮换即可`, 'error', 10000);
        } else {
          showError(e.error);
        }
        break;
    }
  },
});

async function refresh() {
  total = await store.countNotes();
  const notes = await store.getAllNotes();
  const ul = $('notes');
  ul.innerHTML = '';
  for (const n of notes.slice().reverse()) {
    const li = document.createElement('li');
    let text;
    try {
      text = await km.decryptNote(n);
    } catch (err) {
      text = `⚠️ ${err.message}`;
    }
    li.innerHTML = `<div></div><div class="meta">#${n.id} · 密钥 v${n.keyVersion} · ` +
      `${new Date(n.updatedAt).toLocaleString()}</div>`;
    li.firstElementChild.textContent = text;
    ul.appendChild(li);
  }
  $('status2').textContent = `共 ${total} 条 · 当前密钥 v${km.currentVersion}`;
}

async function enterApp() {
  $('auth-box').classList.add('hidden');
  $('main-box').classList.remove('hidden');
  total = await store.countNotes();
  await refresh();
}

$('btn-setup').onclick = async () => {
  try {
    const pw = $('password').value;
    if (!pw) return toast('请先输入口令', 'error');
    await km.setup(pw);
    toast('初始化完成，已生成 v1 密钥', 'success');
    await enterApp();
  } catch (e) { showError(e); }
};

$('btn-unlock').onclick = async () => {
  try {
    await km.unlock($('password').value);
    toast('解锁成功', 'success');
    await enterApp();
  } catch (e) {
    if (e.code === 'UNWRAP_FAILED') showError(new Error('口令错误，请重试'));
    else showError(e);
  }
};

$('btn-add').onclick = async () => {
  try {
    const text = $('note-input').value.trim();
    if (!text) return;
    const enc = await km.encryptNote(text);
    await store.putNote({ ...enc, updatedAt: Date.now() });
    $('note-input').value = '';
    await refresh();
  } catch (e) { showError(e); }
};

$('btn-gen').onclick = async () => {
  try {
    $('btn-gen').disabled = true;
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) {
      const enc = await km.encryptNote(`测试笔记 #${i}：这是一段用于性能测试的内容。`);
      await store.putNote({ ...enc, updatedAt: Date.now() });
    }
    toast(`生成 1000 条耗时 ${(performance.now() - t0).toFixed(0)} ms`, 'info');
    await refresh();
  } catch (e) { showError(e); } finally { $('btn-gen').disabled = false; }
};

$('btn-rotate').onclick = async () => {
  try {
    const newPassword = $('new-password').value || undefined;
    const t0 = performance.now();
    const v = await km.rotate({ newPassword });
    toast(`已切换到密钥 v${v}，迁移耗时 ${(performance.now() - t0).toFixed(0)} ms`, 'success');
    $('new-password').value = '';
    await refresh();
  } catch (e) { showError(e); }
};

// 模拟崩溃：迁移进行中直接刷新，重开解锁后自动续跑
$('btn-crash').onclick = () => location.reload();

// 未处理的异步异常也给出提示，不静默失败
window.addEventListener('unhandledrejection', (e) => showError(e.reason));
