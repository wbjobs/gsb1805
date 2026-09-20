# 本地加密笔记存储（Web Crypto + IndexedDB + Web Worker）

零依赖的浏览器本地加密存储 Demo，支持**密钥轮换**与**可断点续跑的旧数据迁移**。

## 运行

```bash
# 需要通过 HTTP 访问（ES Module Worker 不支持 file://）
python3 -m http.server 8000
# 打开 http://localhost:8000/          —— Demo
# 打开 http://localhost:8000/test/test.html —— 浏览器端冒烟测试
```

Node 端测试（真实 Web Crypto，内存存储）：

```bash
node test/run-tests.mjs
```

## 架构

```
口令 ──PBKDF2(SHA-256, 60万次)──> KEK(AES-GCM) ──包裹──> DEK v1..vN（落盘 keys 表）
笔记 ──DEK AES-GCM(随机IV)──> ciphertext（落盘 notes 表，带 keyVersion）
```

| 模块 | 职责 |
| --- | --- |
| `src/crypto-core.js` | 纯加密原语：KDF、DEK 生成/包裹、AES-GCM 加解密（浏览器/Node 通用） |
| `src/crypto-worker.js` | Web Worker，所有加密操作与 CryptoKey 句柄都在 Worker 内，不阻塞 UI |
| `src/crypto-client.js` | 主线程 RPC 客户端：Promise 化、超时、错误还原 |
| `src/db.js` | IndexedDB 三个仓库：`notes` / `keys` / `meta` |
| `src/key-manager.js` | 初始化、解锁、轮换编排、事件通知 |
| `src/migrator.js` | 批量重加密 + 每批单事务 + 检查点持久化，崩溃可续 |

## 密钥轮换流程

1. （可选）更换口令 → 派生新 KEK，重包裹所有存量 DEK；
2. 生成新版本 DEK，用 KEK 包裹后写入 `keys` 表；
3. 写入 `migration` 检查点 `{from, to, cursor, processed, failed, done:false}`；
4. 切换 `currentKeyVersion` —— **新笔记立即使用新密钥**；
5. 后台迁移：游标分页读取 → Worker 整批重加密 → 单事务写回 → 更新检查点；
6. 全部成功：删除旧 DEK 与检查点；有坏数据：保留旧密钥并上报失败 ID。

## 断点续跑

- 每批 = 一次 IDB 事务（要么全写要么不写）+ 随后持久化检查点；
- 崩溃最多丢失“已写盘但检查点未更新”的一批，重跑时重复加密幂等安全（AES-GCM 随机 IV）；
- 解锁时检测到未完成的 `migration` 自动续跑（Demo 里可点“模拟崩溃”刷新页面验证）。

## 性能设计

- PBKDF2 与所有 AES-GCM 操作均在 Worker 内执行，UI 不冻结；
- 迁移按批（默认 100 条）一次 `postMessage`，批内 `Promise.all` 并行；
- 每批一次事务写盘，批间 `setTimeout(0)` 让出主线程；
- 参考数据：Node 环境下 2000 条（每条 ~120B）全量迁移约 100ms。

## 异常处理

| 场景 | 行为 |
| --- | --- |
| 口令错误 | 解包失败 → `UNWRAP_FAILED` → UI 提示“口令错误” |
| 密文损坏 | 迁移时逐条隔离，记录失败 ID，旧密钥保留，事件上报 |
| Worker 异常/超时 | RPC 统一拒绝并 toast 提示 |
| 迁移中断 | 检查点已落盘，下次解锁自动续跑 |
| 未捕获异常 | `unhandledrejection` 兜底 toast |

## 验收标准对照

- ✅ 轮换后旧笔记可解（测试 3、浏览器冒烟）
- ✅ 新笔记用新密钥（`currentKeyVersion` 即时切换）
- ✅ 迁移中断可续（测试 4：中止→“重启”→自动续跑→全部 v2）
- ✅ 性能可接受（Worker + 批处理，测试 7 计时）
- ✅ 异常有提示（测试 2/5 + UI toast）
