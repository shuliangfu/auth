# Changelog

All notable changes to @dreamer/auth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.1.0] - 2026-07-23

### Added

- **Node.js 22+ compatibility**: `@dreamer/auth` now runs on Deno 2.9+, Bun 1.3+,
  and Node.js 22+. Added `package.json` (`engines.node: ">=22"`, `test:node`
  script via `tsx`), `tsconfig.json`, `.npmrc`, and `.github/workflows/ci.yml`
  (9-job matrix: 3 runtimes × Linux/macOS/Windows). The source uses only
  cross-runtime globals (`atob`/`btoa`/`crypto.subtle`/`fetch`/`Date`/`JSON`),
  so no source changes were required.

### Changed

- **JWT test locale locking** (`tests/jwt.test.ts`): Added module-level
  `setCryptoLocale("zh-CN")` and `setAuthLocale("zh-CN")`. The file's
  assertions depend on `$tr` error messages from two i18n systems —
  `@dreamer/crypto` (`decodeJWT`/`verifyJWT`: "过期", "无效的 JWT Token 格式")
  and auth itself (`issuerMismatch`: "签发者不匹配"). Under CI's English
  locale both returned English and the Chinese assertions failed; locking both
  locales reproduces the local zh-CN behavior deterministically.
- **Compiler libs**: Removed `deno.ns`/`deno.window` from `deno.json`
  `compilerOptions.lib` (standard libs are sufficient; avoids Node global
  conflicts under `nodeModulesDir`).
- **Dependencies**: Bumped `@dreamer/crypto` to ^1.1.0,
  `@dreamer/session` to ^1.1.0, `@dreamer/runtime-adapter` to ^1.2.2,
  `@dreamer/test` to ^1.2.3, `@dreamer/i18n` to ^1.1.2. Added
  `minimumDependencyAge: 0`.
- **Publish**: Removed `--no-check` from `jsr publish` in `publish.yml`.

### Tests

- Cross-runtime: Deno 128 (123 unit + 5 lifecycle) / Bun 123 / Node.js 123,
  all passing.

---

## [1.0.1] - 2026-02-20

### Changed

- **Dependencies**: Bumped @dreamer/crypto to ^1.0.2, @dreamer/test to ^1.0.12.

---

## [1.0.0] - 2026-02-19

### Added

- **Official release**: First official version with stable API.
- **JWT** (`src/jwt.ts`): Sign, verify, decode; HS/RS/ES algorithms; key
  generation.
- **OAuth2** (`src/oauth.ts`): Authorization code, PKCE; token exchange;
  built-in providers (GitHub, Google, WeChat, etc.).
- **Refresh tokens** (`src/refresh.ts`): Access + refresh token pair, refresh
  and revoke.
- **Session** (`src/session.ts`): Session middleware, login/logout, user
  context; `@dreamer/session` integration.
- **Auth helpers**: Bearer/Basic parsing, role and permission checks.
- **Internationalization (i18n)**: Server-side messages (invalid token, exchange
  failed, user info failed, etc.) in en-US and zh-CN via `@dreamer/i18n`; locale
  from `LANGUAGE` / `LC_ALL` / `LANG`; `$tr`, `setAuthLocale`, `detectLocale`
  exported from `./i18n.ts`.

### Compatibility

- Deno 2.6+
- Bun 1.3.5+
