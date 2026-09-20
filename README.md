# 本地加密笔记（Web Crypto + IndexedDB + Web Worker）

纯前端、零第三方运行时依赖的本地加密存储。所有数据仅存在浏览器 IndexedDB 中，
密码从不出设备；重密码学操作（PBKDF2 派生、批量加解密、密钥迁移）运行在
Web Worker 中，不阻塞 UI。

## 运行

```bash
npm start          # http://localhost:5173（零依赖 Node 静态服务器）
npm test           # Node 内置 test runner，14 个用例
```

> Web Crypto 要求 secure context：使用 `localhost` 或 HTTPS 打开。

## 密钥体系

- **KEK（主密钥）**：密码经 `PBKDF2(SHA-256, 310_000 轮, 16 字节随机 salt)` 派生，
  `AES-KW` 用途、不可导出（`extractable=false`），只用于包装 DEK。
- **DEK（数据密钥）**：每条密钥版本一把 `AES-GCM-256` 随机密钥；密文信封为
  `{ v:1, kid, iv(12B), ct }`，每条密文独立 IV。
- **校验**：解锁时先 AES-KW 解封（密码错误即失败），再解密一条 `verifier` 密文二次确认。

## 轮换与迁移

1. **原子轮换**（`Keyring.rotate`）：校验当前密码 → 生成新 KEK 与**新 DEK** →
   用新 KEK 重新包装**所有旧 DEK** → 单 IndexedDB 事务提交
   （`keys` + `meta` 两个 store）。**提交后旧笔记立即可用新密码解开**，
   即使迁移尚未开始（旧 DEK 还在，只是换了包装）。
2. **后台迁移**（`Migrator`）：把旧 kid 的笔记用旧 DEK 解密、新 DEK 重新加密。
   - 分批处理（默认 25 条/批，批内并发 4），批间让出事件循环。
   - **断点续迁**：每批结束把状态写入 `migration` store；每批重新查询
     “kid ≠ 活动密钥”的首页，已迁条目自动出列，重放幂等安全。刷新/崩溃后
     解锁时自动 `resumeMigration`，也可手动暂停/继续。
   - 全部成功后才删除旧密钥版本；存在失败条目时保留旧密钥，笔记依旧可读。
   - 更新旧笔记时就地用活动密钥重加密（更新即升级），减少迁移量。

## 异常处理

- 错误均带 `code`（`BAD_PASSWORD` / `DECRYPT_FAILED` / `IDB_BLOCKED` /
  `ROTATION_BUSY` / `TARGET_MISMATCH` …），UI 映射为中文 toast 提示。
- 单条笔记迁移失败记录到 `failures` store，不阻塞其它条目，避免零进展死循环；
  修复后“继续”会清除失败记录并重试。
- 存储致命错误时迁移断点保留为 `paused`，下次可续。
- Worker 构造/加载失败时自动降级为主线程 + IndexedDB（再降级内存存储）。

## 性能

- PBKDF2 只在初始化/解锁/轮换时执行；批量迁移使用批处理 + 有界并发，
  每批结束才写一次断点。
- 界面提供“性能测试”：写入 200 条 + 一次轮换迁移并上报耗时。
  实际耗时主要取决于设备 PBKDF2（310k 轮）与笔记大小，GCM 加解密本身为每秒数十 MB 级。

## 目录

- `src/crypto-core.mjs` — Web Crypto 原语（KDF、包装、信封加解密）
- `src/keyring.mjs` — 密钥版本、解锁、原子轮换
- `src/migration.mjs` — 分批、可暂停、断点续迁的迁移器
- `src/vault.mjs` — 门面（笔记 CRUD + 轮换 + 迁移编排）
- `src/idb-adapter.mjs` / `src/memory-adapter.mjs` — 存储适配（IndexedDB / 内存）
- `src/worker.mjs` / `src/vault-client.mjs` — Worker RPC 与主线程代理（含降级）
- `src/app.mjs` + `index.html` — 演示界面
- `test/` — 覆盖全部验收标准的用例
