# Changelog

All notable changes to @dreamer/auth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
