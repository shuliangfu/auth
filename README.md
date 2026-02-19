# @dreamer/auth

> A user authentication package for Deno and Bun. Full auth solution: JWT,
> OAuth2, Session, and permission checks.

**中文**: [docs/zh-CN/README.md](./docs/zh-CN/README.md) · **Test report (EN)**:
[docs/en-US/TEST_REPORT.md](./docs/en-US/TEST_REPORT.md)

[![JSR](https://jsr.io/badges/@dreamer/auth)](https://jsr.io/@dreamer/auth)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-128%20passed-brightgreen)](./docs/en-US/TEST_REPORT.md)

**Changelog (latest)**: [1.0.0] - 2026-02-19 — First stable release. Added: JWT,
OAuth2, refresh tokens, Session, auth helpers, i18n. Full history:
[English](./docs/en-US/CHANGELOG.md) | [中文](./docs/zh-CN/CHANGELOG.md)

---

## 🎯 Features

User authentication package with a full abstraction layer, multiple auth
methods, login, permission control, and API protection.

---

## 📦 Installation

### Deno

```bash
deno add jsr:@dreamer/auth
```

### Bun

```bash
bunx jsr add @dreamer/auth
```

---

## 🌍 Environment Compatibility

| Environment      | Version | Status                                                                  |
| ---------------- | ------- | ----------------------------------------------------------------------- |
| **Deno**         | 2.5+    | ✅ Fully supported                                                      |
| **Bun**          | 1.0+    | ✅ Fully supported                                                      |
| **Server**       | -       | ✅ Supported (Deno and Bun runtimes)                                    |
| **Dependencies** | -       | 📦 @dreamer/crypto (JWT) · 📦 @dreamer/session (Session auth, optional) |

---

## ✨ Characteristics

- **JWT authentication**:
  - JWT signing (HS256/RS256/ES256 and more)
  - JWT verification
  - JWT decode (no signature verification)
  - Token expiry check
  - RSA/ECDSA key pair generation
- **Token parsing**:
  - Bearer Token parsing
  - Basic Auth parsing and header generation
  - Authorization header handling
- **OAuth2 authentication**:
  - Authorization Code flow
  - PKCE (recommended for public clients)
  - Token exchange and refresh
  - Built-in providers (GitHub, Google, WeChat, WeCom, DingTalk, GitLab, Gitee)
  - User info parsers
- **Token refresh**:
  - Access Token + Refresh Token
  - Refresh and revoke
  - In-memory store (custom store supported)
  - Expiry handling
- **Session authentication**:
  - Session auth based on @dreamer/session
  - Login / logout
  - Session middleware
  - Auth-protection middleware
- **Permission checks**:
  - Role checks (hasRole, hasAnyRole, hasAllRoles)
  - Permission checks (hasPermission, hasAnyPermission, hasAllPermissions)
  - Path matching and route protection
  - Path-based role configuration

---

## 🎯 Use Cases

- **API auth**: Protect APIs with JWT
- **Third-party login**: GitHub, Google, WeChat via OAuth2
- **Session management**: Session-based login state
- **Access control**: Role and permission checks for fine-grained control
- **Token refresh**: Seamless access token refresh

---

## 🚀 Quick Start

### JWT signing and verification

```typescript
import { decodeToken, signToken, verifyToken } from "@dreamer/auth/jwt";

// Sign JWT (secret at least 32 chars)
const token = await signToken(
  { userId: "123", username: "admin" },
  "your-secret-key-at-least-32-chars!",
  {
    expiresIn: "1h",
    issuer: "my-app",
  },
);

// Verify JWT
try {
  const payload = await verifyToken(
    token,
    "your-secret-key-at-least-32-chars!",
  );
  console.log(payload.userId); // "123"
} catch (error) {
  console.error("Token verification failed:", error.message);
}

// Decode JWT (no signature verification)
const decoded = decodeToken(token);
console.log(decoded.header.alg); // "HS256"
console.log(decoded.payload.userId); // "123"
```

### Bearer Token parsing

```typescript
import { isJwtExpired, parseBearerToken, parseJwt } from "@dreamer/auth";

// Parse token from request header
const authHeader = request.headers.get("authorization");
const token = parseBearerToken(authHeader);

if (token) {
  // Parse JWT payload
  const payload = parseJwt(token);

  // Check expiry
  if (isJwtExpired(payload)) {
    console.log("Token expired");
  }
}
```

---

## 🎨 Examples

### OAuth2 third-party login

```typescript
import {
  generatePKCE,
  generateState,
  GitHubProvider,
  OAuth2Client,
  parseGitHubUser,
} from "@dreamer/auth/oauth";

// Create GitHub OAuth2 client
const github = new OAuth2Client({
  ...GitHubProvider,
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "http://localhost:3000/callback",
});

// Build authorization URL (with PKCE)
const pkce = await generatePKCE();
const state = generateState();

const authUrl = github.getAuthorizationUrl({
  scope: "user:email",
  state,
  codeChallenge: pkce.codeChallenge,
  codeChallengeMethod: pkce.codeChallengeMethod,
});

// After user authorizes, exchange code for tokens
const tokens = await github.exchangeCode(code, {
  codeVerifier: pkce.codeVerifier,
});

// Get user info
const rawUser = await github.getUserInfoRaw(tokens.access_token);
const user = parseGitHubUser(rawUser);
console.log(user.username); // GitHub username
```

### Token refresh

```typescript
import { TokenManager } from "@dreamer/auth/refresh";

// Create token manager
const tokenManager = new TokenManager({
  accessTokenSecret: "access-secret-at-least-32-chars!",
  refreshTokenSecret: "refresh-secret-at-least-32-chars",
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  issuer: "my-app",
});

// Generate token pair on login
const tokens = await tokenManager.generateTokenPair({
  userId: "123",
  username: "admin",
  roles: ["admin"],
});

console.log(tokens.accessToken); // Short-lived access token
console.log(tokens.refreshToken); // Long-lived refresh token

// Verify access token
const payload = await tokenManager.verifyAccessToken(tokens.accessToken);

// Refresh when access token is about to expire
if (tokenManager.shouldRefresh(tokens.accessToken)) {
  const newTokens = await tokenManager.refresh(tokens.refreshToken);
  console.log(newTokens.accessToken); // New access token
}

// Revoke on logout
await tokenManager.revoke(tokens.refreshToken);
```

### Session authentication

```typescript
import { createAuthSession } from "@dreamer/auth/session";
import { MemorySessionAdapter } from "@dreamer/session";

// Create session store
const store = new MemorySessionAdapter();

// Create auth session manager
const authSession = createAuthSession({
  store,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  },
});

// Login
await authSession.login(ctx, {
  id: "123",
  username: "admin",
  roles: ["admin"],
});

// Check authenticated
if (authSession.isAuthenticated(ctx)) {
  const user = authSession.getUser(ctx);
  console.log(user?.username); // "admin"
}

// Logout
await authSession.logout(ctx);
```

### Permission checks

```typescript
import {
  hasAllPermissions,
  hasAllRoles,
  hasAnyPermission,
  hasAnyRole,
  hasPermission,
  hasRole,
} from "@dreamer/auth";

const user = {
  id: "123",
  username: "admin",
  roles: ["admin", "editor"],
  permissions: ["users:read", "users:write", "posts:read"],
};

// Role checks
if (hasRole(user, "admin")) {
  console.log("User is admin");
}

if (hasAnyRole(user, ["admin", "moderator"])) {
  console.log("User has admin or moderator role");
}

if (hasAllRoles(user, ["admin", "editor"])) {
  console.log("User is both admin and editor");
}

// Permission checks
if (hasPermission(user, "users:write")) {
  console.log("User can write user data");
}

if (hasAnyPermission(user, ["users:read", "users:write"])) {
  console.log("User has user-related permissions");
}

if (hasAllPermissions(user, ["users:read", "users:write"])) {
  console.log("User has full user read/write permissions");
}
```

---

## 📚 API Reference

### JWT module (`@dreamer/auth/jwt`)

#### signToken

Generate JWT token.

```typescript
function signToken(
  payload: Record<string, unknown>,
  secret: string | CryptoKey,
  options?: SignTokenOptions,
): Promise<string>;
```

**Parameters**:

| Parameter | Type                      | Required | Description                                     |
| --------- | ------------------------- | -------- | ----------------------------------------------- |
| payload   | `Record<string, unknown>` | ✅       | JWT payload                                     |
| secret    | `string \| CryptoKey`     | ✅       | Secret (string at least 32 chars, or CryptoKey) |
| options   | `SignTokenOptions`        | ❌       | Sign options                                    |

**SignTokenOptions**:

| Option    | Type           | Description                     |
| --------- | -------------- | ------------------------------- |
| algorithm | `JwtAlgorithm` | Algorithm (default HS256)       |
| expiresIn | `string`       | Expiry (e.g. "1h", "24h", "7d") |
| issuer    | `string`       | Issuer                          |
| audience  | `string`       | Audience                        |
| subject   | `string`       | Subject                         |

#### verifyToken

Verify JWT token.

```typescript
function verifyToken(
  token: string,
  secret: string | CryptoKey,
  options?: VerifyTokenOptions,
): Promise<JWTPayload>;
```

**VerifyTokenOptions**:

| Option           | Type                             | Description                 |
| ---------------- | -------------------------------- | --------------------------- |
| issuer           | `string`                         | Verify issuer               |
| audience         | `string`                         | Verify audience             |
| ignoreExpiration | `boolean`                        | Ignore expiry check         |
| algorithm        | `JWTAlgorithm \| JWTAlgorithm[]` | Allowed algorithm whitelist |

#### Other JWT functions

| Function                             | Description                     |
| ------------------------------------ | ------------------------------- |
| `decodeToken(token)`                 | Decode JWT (no signature check) |
| `isTokenExpired(token)`              | Check if token is expired       |
| `getTokenExpiration(token)`          | Get token expiration timestamp  |
| `getTokenRemainingTime(token)`       | Get remaining valid time        |
| `generateRSAKeyPair(modulusLength?)` | Generate RSA key pair           |
| `generateECKeyPair(namedCurve?)`     | Generate ECDSA key pair         |

---

### Token parsing module (`@dreamer/auth`)

| Function                                    | Description               |
| ------------------------------------------- | ------------------------- |
| `parseBearerToken(authHeader)`              | Parse Bearer token        |
| `parseBasicAuth(authHeader)`                | Parse Basic Auth          |
| `createBasicAuthHeader(username, password)` | Create Basic Auth header  |
| `createBearerAuthHeader(token)`             | Create Bearer Auth header |
| `parseJwt(token)`                           | Parse JWT payload         |
| `isJwtExpired(payload)`                     | Check if JWT is expired   |
| `validateJwtClaims(payload, config)`        | Validate JWT claims       |
| `extractUserFromJwt(payload)`               | Extract user from JWT     |

---

### OAuth2 module (`@dreamer/auth/oauth`)

#### OAuth2Client

OAuth2 client class.

```typescript
class OAuth2Client {
  constructor(config: OAuth2Config);
  getAuthorizationUrl(options?: AuthorizationUrlOptions): string;
  exchangeCode(
    code: string,
    options?: ExchangeCodeOptions,
  ): Promise<OAuth2TokenResponse>;
  refreshToken(refreshToken: string): Promise<OAuth2TokenResponse>;
  getUserInfoRaw(accessToken: string): Promise<Record<string, unknown>>;
}
```

#### Built-in providers

| Provider           | Description     |
| ------------------ | --------------- |
| `GitHubProvider`   | GitHub OAuth2   |
| `GoogleProvider`   | Google OAuth2   |
| `WeChatProvider`   | WeChat OAuth2   |
| `WeComProvider`    | WeCom OAuth2    |
| `DingTalkProvider` | DingTalk OAuth2 |
| `GitLabProvider`   | GitLab OAuth2   |
| `GiteeProvider`    | Gitee OAuth2    |

#### User info parsers

| Function          | Description       |
| ----------------- | ----------------- |
| `parseGitHubUser` | Parse GitHub user |
| `parseGoogleUser` | Parse Google user |
| `parseWeChatUser` | Parse WeChat user |
| `parseGitLabUser` | Parse GitLab user |
| `parseGiteeUser`  | Parse Gitee user  |

#### Helpers

| Function          | Description    |
| ----------------- | -------------- |
| `generatePKCE()`  | Generate PKCE  |
| `generateState()` | Generate state |

---

### Token refresh module (`@dreamer/auth/refresh`)

#### TokenManager

Token manager class.

```typescript
class TokenManager {
  constructor(options: TokenManagerOptions);
  generateTokenPair(
    payload: Record<string, unknown>,
    options?: GenerateTokenOptions,
  ): Promise<TokenPair>;
  refresh(
    refreshToken: string,
    newPayload?: Record<string, unknown>,
  ): Promise<TokenPair>;
  verifyAccessToken(accessToken: string): Promise<JWTPayload>;
  revoke(refreshToken: string): Promise<void>;
  revokeAllByUser(userId: string): Promise<void>;
  shouldRefresh(accessToken: string, threshold?: number): boolean;
  isAccessTokenExpired(accessToken: string): boolean;
}
```

**TokenManagerOptions**:

| Option             | Type                  | Description                       |
| ------------------ | --------------------- | --------------------------------- |
| accessTokenSecret  | `string \| CryptoKey` | Access token secret               |
| refreshTokenSecret | `string \| CryptoKey` | Refresh token secret              |
| accessTokenExpiry  | `string`              | Access token expiry (default 15m) |
| refreshTokenExpiry | `string`              | Refresh token expiry (default 7d) |
| store              | `TokenStore`          | Token store (default in-memory)   |
| issuer             | `string`              | Issuer                            |
| audience           | `string`              | Audience                          |

#### MemoryTokenStore

In-memory token store implementing `TokenStore`.

---

### Session auth module (`@dreamer/auth/session`)

#### AuthSessionManager

Session auth manager class.

```typescript
class AuthSessionManager {
  constructor(options: AuthSessionOptions);
  login(ctx: HttpContext, user: AuthUser): Promise<void>;
  logout(ctx: HttpContext): Promise<void>;
  isAuthenticated(ctx: HttpContext): boolean;
  getUser(ctx: HttpContext): AuthUser | null;
  loadSession(ctx: HttpContext): Promise<boolean>;
  middleware(): (ctx: HttpContext, next: () => Promise<void>) => Promise<void>;
  requireAuth(
    redirectUrl?: string,
  ): (ctx: HttpContext, next: () => Promise<void>) => Promise<Response | void>;
}
```

**AuthSessionOptions**:

| Option          | Type                                            | Description                         |
| --------------- | ----------------------------------------------- | ----------------------------------- |
| store           | `SessionStore`                                  | Session store adapter               |
| cookieName      | `string`                                        | Cookie name (default authSessionId) |
| maxAge          | `number`                                        | Session expiry in ms (default 24h)  |
| cookie          | `CookieOptions`                                 | Cookie options                      |
| serializeUser   | `(user: AuthUser) => AuthUser`                  | User serialization                  |
| deserializeUser | `(user: AuthUser) => Promise<AuthUser \| null>` | User deserialization                |

---

### Permission checks (`@dreamer/auth`)

#### Role checks

| Function                   | Description         |
| -------------------------- | ------------------- |
| `hasRole(user, role)`      | Check for one role  |
| `hasAnyRole(user, roles)`  | Check for any role  |
| `hasAllRoles(user, roles)` | Check for all roles |

#### Permission checks

| Function                               | Description               |
| -------------------------------------- | ------------------------- |
| `hasPermission(user, permission)`      | Check for one permission  |
| `hasAnyPermission(user, permissions)`  | Check for any permission  |
| `hasAllPermissions(user, permissions)` | Check for all permissions |

#### Path matching

| Function                        | Description                 |
| ------------------------------- | --------------------------- |
| `matchPath(path, patterns)`     | Match path to patterns      |
| `requiresAuth(path, options)`   | Check if path needs auth    |
| `getRequiredRoles(path, roles)` | Get required roles for path |

---

## 📊 Test Report

| Metric        | Deno | Bun  |
| ------------- | ---- | ---- |
| **Total**     | 128  | 123  |
| **Passed**    | 128  | 123  |
| **Failed**    | 0    | 0    |
| **Pass rate** | 100% | 100% |

See [docs/en-US/TEST_REPORT.md](./docs/en-US/TEST_REPORT.md) for the full
report.

---

## 📝 Notes

- **Secret length**: HMAC secrets must be at least 32 characters; use strong
  secrets in production.
- **Algorithm whitelist**: When verifying JWT, specify allowed algorithms to
  avoid algorithm confusion.
- **Token storage**: Use a persistent store (e.g. Redis) for refresh tokens in
  production.
- **PKCE**: Use PKCE for OAuth2 public clients (e.g. SPA, mobile).
- **Session cookies**: Prefer `httpOnly`, `secure`, and `sameSite` cookie
  options.

---

## 🤝 Contributing

Issues and Pull Requests are welcome.

---

## 📄 License

Apache License 2.0 — see [LICENSE](./LICENSE).

---

<div align="center">

**Made with ❤️ by Dreamer Team**

</div>
