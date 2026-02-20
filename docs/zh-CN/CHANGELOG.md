# 变更日志

@dreamer/auth 的所有重要变更均记录于此。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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
