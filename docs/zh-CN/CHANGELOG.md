# 变更日志

@dreamer/auth 的所有重要变更均记录于此。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.1.0] - 2026-07-23

### 新增

- **Node.js 22+ 兼容**：`@dreamer/auth` 现可运行于 Deno 2.9+、Bun 1.3+ 与
  Node.js 22+。新增 `package.json`（`engines.node: ">=22"`、经 `tsx` 的
  `test:node` 脚本）、`tsconfig.json`、`.npmrc` 与 `.github/workflows/ci.yml`
  （9 任务矩阵：3 运行时 × Linux/macOS/Windows）。源码仅使用跨运行时全局
  （`atob`/`btoa`/`crypto.subtle`/`fetch`/`Date`/`JSON`），无需改动源码。

### 变更

- **JWT 测试 locale 锁定**（`tests/jwt.test.ts`）：模块级新增
  `setCryptoLocale("zh-CN")` 与 `setAuthLocale("zh-CN")`。本文件断言依赖
  两套 i18n 系统的 `$tr` 错误文案——`@dreamer/crypto`
  （`decodeJWT`/`verifyJWT`："过期"、"无效的 JWT Token 格式"）与 auth 自身
  （`issuerMismatch`："签发者不匹配"）。CI 英文 locale 下两者均返回英文致中文断言
  失败；同时锁定两者 locale 即可确定性复现本地 zh-CN 行为。
- **编译 lib**：从 `deno.json` 的 `compilerOptions.lib` 移除
  `deno.ns`/`deno.window`（标准 lib 已足够，避免 `nodeModulesDir` 下与 Node 全局
  冲突）。
- **依赖**：升级 `@dreamer/crypto` 至 ^1.1.0、`@dreamer/session` 至 ^1.1.0、
  `@dreamer/runtime-adapter` 至 ^1.2.2、`@dreamer/test` 至 ^1.2.3、
  `@dreamer/i18n` 至 ^1.1.2。新增 `minimumDependencyAge: 0`。
- **发布**：`publish.yml` 中移除 `jsr publish` 的 `--no-check`。

### 测试

- 跨运行时：Deno 128（123 单元 + 5 生命周期）/ Bun 123 / Node.js 123，全部通过。

---

## [1.0.1] - 2026-02-20

### 变更

- **依赖**：升级 @dreamer/crypto 至 ^1.0.2、@dreamer/test 至 ^1.0.12。

---

## [1.0.0] - 2026-02-19

### 新增

- **正式版发布**：首个正式版本，API 稳定。
- **JWT**（`src/jwt.ts`）：签名、验证、解码；HS/RS/ES 算法；密钥生成。
- **OAuth2**（`src/oauth.ts`）：授权码、PKCE；Token 交换；内置
  Provider（GitHub、Google、微信等）。
- **刷新令牌**（`src/refresh.ts`）：Access + Refresh 双令牌；刷新与撤销。
- **Session**（`src/session.ts`）：Session 中间件、登录/登出、用户上下文；与
  `@dreamer/session` 集成。
- **认证辅助**：Bearer/Basic 解析、角色与权限校验。
- **国际化（i18n）**：服务端文案（无效 Token、交换失败、用户信息获取失败等）提供
  en-US 与 zh-CN，基于 `@dreamer/i18n`；语言由 `LANGUAGE` / `LC_ALL` / `LANG`
  决定；从 `./i18n.ts` 导出 `$tr`、`setAuthLocale`、`detectLocale`。

### 兼容性

- Deno 2.6+
- Bun 1.3.5+
