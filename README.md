# @dreamer/auth

> 一个兼容 Deno 和 Bun 的用户认证库，提供完整的认证解决方案，支持 JWT、OAuth2、Session 认证和权限验证

[![JSR](https://jsr.io/badges/@dreamer/auth)](https://jsr.io/@dreamer/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-123%20passed-brightgreen)](./TEST_REPORT.md)

---

## 🎯 功能

用户认证库，提供完整的认证抽象层，支持多种认证方式，用于用户登录、权限控制、API 保护等场景。

---

## 📦 安装

### Deno

```bash
deno add jsr:@dreamer/auth
```

### Bun

```bash
bunx jsr add @dreamer/auth
```

---

## 🌍 环境兼容性

| 环境       | 版本要求 | 状态                                                                     |
| ---------- | -------- | ------------------------------------------------------------------------ |
| **Deno**   | 2.5+     | ✅ 完全支持                                                              |
| **Bun**    | 1.0+     | ✅ 完全支持                                                              |
| **服务端** | -        | ✅ 支持（兼容 Deno 和 Bun 运行时）                                       |
| **依赖**   | -        | 📦 @dreamer/crypto（JWT 功能）<br>📦 @dreamer/session（Session 认证，可选） |

---

## ✨ 特性

- **JWT 认证**：
  - JWT 签名生成（支持 HS256/RS256/ES256 等多种算法）
  - JWT 签名验证
  - JWT 解码（不验证签名）
  - Token 过期检查
  - RSA/ECDSA 密钥对生成
- **Token 解析**：
  - Bearer Token 解析
  - Basic Auth 解析和生成
  - Authorization 头处理
- **OAuth2 认证**：
  - Authorization Code 授权码流程
  - PKCE 扩展（推荐用于公开客户端）
  - Token 交换和刷新
  - 内置 Provider（GitHub、Google、微信、企业微信、钉钉、GitLab、Gitee）
  - 用户信息解析器
- **Token 刷新机制**：
  - Access Token + Refresh Token 双令牌机制
  - Token 刷新和撤销
  - 内存存储（支持自定义存储）
  - 自动过期管理
- **Session 认证**：
  - 基于 @dreamer/session 的 Session 认证
  - 用户登录/登出
  - Session 中间件
  - 认证保护中间件
- **权限验证**：
  - 角色检查（hasRole、hasAnyRole、hasAllRoles）
  - 权限检查（hasPermission、hasAnyPermission、hasAllPermissions）
  - 路径匹配和路由保护
  - 基于路径的角色配置

---

## 🎯 使用场景

- **API 认证**：使用 JWT 保护 API 接口
- **第三方登录**：使用 OAuth2 实现 GitHub、Google、微信登录
- **用户会话管理**：使用 Session 管理用户登录状态
- **权限控制**：使用角色和权限验证实现细粒度的访问控制
- **Token 刷新**：实现无感知的 Token 自动刷新

---

## 🚀 快速开始

### JWT 签名和验证

```typescript
import { signToken, verifyToken, decodeToken } from "@dreamer/auth/jwt";

// 生成 JWT（密钥至少 32 字符）
const token = await signToken(
  { userId: "123", username: "admin" },
  "your-secret-key-at-least-32-chars!",
  {
    expiresIn: "1h",
    issuer: "my-app",
  }
);

// 验证 JWT
try {
  const payload = await verifyToken(
    token,
    "your-secret-key-at-least-32-chars!"
  );
  console.log(payload.userId); // "123"
} catch (error) {
  console.error("Token 验证失败:", error.message);
}

// 解码 JWT（不验证签名）
const decoded = decodeToken(token);
console.log(decoded.header.alg); // "HS256"
console.log(decoded.payload.userId); // "123"
```

### Bearer Token 解析

```typescript
import { parseBearerToken, parseJwt, isJwtExpired } from "@dreamer/auth";

// 从请求头解析 Token
const authHeader = request.headers.get("authorization");
const token = parseBearerToken(authHeader);

if (token) {
  // 解析 JWT payload
  const payload = parseJwt(token);

  // 检查是否过期
  if (isJwtExpired(payload)) {
    console.log("Token 已过期");
  }
}
```

---

## 🎨 使用示例

### OAuth2 第三方登录

```typescript
import {
  OAuth2Client,
  GitHubProvider,
  generateState,
  generatePKCE,
  parseGitHubUser,
} from "@dreamer/auth/oauth";

// 创建 GitHub OAuth2 客户端
const github = new OAuth2Client({
  ...GitHubProvider,
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "http://localhost:3000/callback",
});

// 生成授权 URL（带 PKCE）
const pkce = await generatePKCE();
const state = generateState();

const authUrl = github.getAuthorizationUrl({
  scope: "user:email",
  state,
  codeChallenge: pkce.codeChallenge,
  codeChallengeMethod: pkce.codeChallengeMethod,
});

// 用户授权后，交换 Token
const tokens = await github.exchangeCode(code, {
  codeVerifier: pkce.codeVerifier,
});

// 获取用户信息
const rawUser = await github.getUserInfoRaw(tokens.access_token);
const user = parseGitHubUser(rawUser);
console.log(user.username); // GitHub 用户名
```

### Token 刷新机制

```typescript
import { TokenManager } from "@dreamer/auth/refresh";

// 创建 Token 管理器
const tokenManager = new TokenManager({
  accessTokenSecret: "access-secret-at-least-32-chars!",
  refreshTokenSecret: "refresh-secret-at-least-32-chars",
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  issuer: "my-app",
});

// 登录时生成 Token 对
const tokens = await tokenManager.generateTokenPair({
  userId: "123",
  username: "admin",
  roles: ["admin"],
});

console.log(tokens.accessToken); // 短期有效的 Access Token
console.log(tokens.refreshToken); // 长期有效的 Refresh Token

// 验证 Access Token
const payload = await tokenManager.verifyAccessToken(tokens.accessToken);

// Access Token 快过期时刷新
if (tokenManager.shouldRefresh(tokens.accessToken)) {
  const newTokens = await tokenManager.refresh(tokens.refreshToken);
  console.log(newTokens.accessToken); // 新的 Access Token
}

// 登出时撤销 Token
await tokenManager.revoke(tokens.refreshToken);
```

### Session 认证

```typescript
import { createAuthSession } from "@dreamer/auth/session";
import { MemorySessionAdapter } from "@dreamer/session";

// 创建 Session 存储
const store = new MemorySessionAdapter();

// 创建认证 Session 管理器
const authSession = createAuthSession({
  store,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 天
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  },
});

// 登录
await authSession.login(ctx, {
  id: "123",
  username: "admin",
  roles: ["admin"],
});

// 检查是否已认证
if (authSession.isAuthenticated(ctx)) {
  const user = authSession.getUser(ctx);
  console.log(user?.username); // "admin"
}

// 登出
await authSession.logout(ctx);
```

### 权限验证

```typescript
import {
  hasRole,
  hasAnyRole,
  hasAllRoles,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
} from "@dreamer/auth";

const user = {
  id: "123",
  username: "admin",
  roles: ["admin", "editor"],
  permissions: ["users:read", "users:write", "posts:read"],
};

// 角色检查
if (hasRole(user, "admin")) {
  console.log("用户是管理员");
}

if (hasAnyRole(user, ["admin", "moderator"])) {
  console.log("用户有管理权限");
}

if (hasAllRoles(user, ["admin", "editor"])) {
  console.log("用户同时是管理员和编辑");
}

// 权限检查
if (hasPermission(user, "users:write")) {
  console.log("用户可以写入用户数据");
}

if (hasAnyPermission(user, ["users:read", "users:write"])) {
  console.log("用户有用户相关权限");
}

if (hasAllPermissions(user, ["users:read", "users:write"])) {
  console.log("用户有完整的用户读写权限");
}
```

---

## 📚 API 文档

### JWT 模块 (`@dreamer/auth/jwt`)

#### signToken

生成 JWT Token。

```typescript
function signToken(
  payload: Record<string, unknown>,
  secret: string | CryptoKey,
  options?: SignTokenOptions
): Promise<string>;
```

**参数**：

| 参数      | 类型                     | 必填 | 说明                                  |
| --------- | ------------------------ | ---- | ------------------------------------- |
| payload   | `Record<string, unknown>` | ✅   | JWT 载荷                              |
| secret    | `string \| CryptoKey`     | ✅   | 密钥（字符串至少 32 字符，或 CryptoKey） |
| options   | `SignTokenOptions`        | ❌   | 签名选项                              |

**SignTokenOptions**：

| 选项       | 类型           | 说明                           |
| ---------- | -------------- | ------------------------------ |
| algorithm  | `JwtAlgorithm` | 算法（默认 HS256）             |
| expiresIn  | `string`       | 过期时间（如 "1h", "24h", "7d"） |
| issuer     | `string`       | 签发者                         |
| audience   | `string`       | 受众                           |
| subject    | `string`       | 主题                           |

#### verifyToken

验证 JWT Token。

```typescript
function verifyToken(
  token: string,
  secret: string | CryptoKey,
  options?: VerifyTokenOptions
): Promise<JWTPayload>;
```

**VerifyTokenOptions**：

| 选项             | 类型                            | 说明                       |
| ---------------- | ------------------------------- | -------------------------- |
| issuer           | `string`                        | 验证签发者                 |
| audience         | `string`                        | 验证受众                   |
| ignoreExpiration | `boolean`                       | 是否忽略过期检查           |
| algorithm        | `JWTAlgorithm \| JWTAlgorithm[]` | 允许的算法白名单           |

#### 其他 JWT 函数

| 函数                    | 说明                     |
| ----------------------- | ------------------------ |
| `decodeToken(token)`    | 解码 JWT（不验证签名）   |
| `isTokenExpired(token)` | 检查 Token 是否过期      |
| `getTokenExpiration(token)` | 获取 Token 过期时间戳 |
| `getTokenRemainingTime(token)` | 获取 Token 剩余有效时间 |
| `generateRSAKeyPair(modulusLength?)` | 生成 RSA 密钥对 |
| `generateECKeyPair(namedCurve?)` | 生成 ECDSA 密钥对 |

---

### Token 解析模块 (`@dreamer/auth`)

| 函数                               | 说明                      |
| ---------------------------------- | ------------------------- |
| `parseBearerToken(authHeader)`     | 解析 Bearer Token         |
| `parseBasicAuth(authHeader)`       | 解析 Basic Auth           |
| `createBasicAuthHeader(username, password)` | 创建 Basic Auth 头 |
| `createBearerAuthHeader(token)`    | 创建 Bearer Auth 头       |
| `parseJwt(token)`                  | 解析 JWT payload          |
| `isJwtExpired(payload)`            | 检查 JWT 是否过期         |
| `validateJwtClaims(payload, config)` | 验证 JWT Claims        |
| `extractUserFromJwt(payload)`      | 从 JWT 提取用户信息       |

---

### OAuth2 模块 (`@dreamer/auth/oauth`)

#### OAuth2Client

OAuth2 客户端类。

```typescript
class OAuth2Client {
  constructor(config: OAuth2Config);
  getAuthorizationUrl(options?: AuthorizationUrlOptions): string;
  exchangeCode(code: string, options?: ExchangeCodeOptions): Promise<OAuth2TokenResponse>;
  refreshToken(refreshToken: string): Promise<OAuth2TokenResponse>;
  getUserInfoRaw(accessToken: string): Promise<Record<string, unknown>>;
}
```

#### 内置 Provider

| Provider          | 说明           |
| ----------------- | -------------- |
| `GitHubProvider`  | GitHub OAuth2  |
| `GoogleProvider`  | Google OAuth2  |
| `WeChatProvider`  | 微信 OAuth2    |
| `WeComProvider`   | 企业微信 OAuth2 |
| `DingTalkProvider`| 钉钉 OAuth2    |
| `GitLabProvider`  | GitLab OAuth2  |
| `GiteeProvider`   | Gitee OAuth2   |

#### 用户信息解析器

| 函数              | 说明               |
| ----------------- | ------------------ |
| `parseGitHubUser` | 解析 GitHub 用户   |
| `parseGoogleUser` | 解析 Google 用户   |
| `parseWeChatUser` | 解析微信用户       |
| `parseGitLabUser` | 解析 GitLab 用户   |
| `parseGiteeUser`  | 解析 Gitee 用户    |

#### 辅助函数

| 函数             | 说明                |
| ---------------- | ------------------- |
| `generatePKCE()` | 生成 PKCE 参数      |
| `generateState()`| 生成 state 参数     |

---

### Token 刷新模块 (`@dreamer/auth/refresh`)

#### TokenManager

Token 管理器类。

```typescript
class TokenManager {
  constructor(options: TokenManagerOptions);
  generateTokenPair(payload: Record<string, unknown>, options?: GenerateTokenOptions): Promise<TokenPair>;
  refresh(refreshToken: string, newPayload?: Record<string, unknown>): Promise<TokenPair>;
  verifyAccessToken(accessToken: string): Promise<JWTPayload>;
  revoke(refreshToken: string): Promise<void>;
  revokeAllByUser(userId: string): Promise<void>;
  shouldRefresh(accessToken: string, threshold?: number): boolean;
  isAccessTokenExpired(accessToken: string): boolean;
}
```

**TokenManagerOptions**：

| 选项                | 类型                    | 说明                           |
| ------------------- | ----------------------- | ------------------------------ |
| accessTokenSecret   | `string \| CryptoKey`   | Access Token 密钥              |
| refreshTokenSecret  | `string \| CryptoKey`   | Refresh Token 密钥             |
| accessTokenExpiry   | `string`                | Access Token 过期时间（默认 15m） |
| refreshTokenExpiry  | `string`                | Refresh Token 过期时间（默认 7d） |
| store               | `TokenStore`            | Token 存储（默认内存存储）      |
| issuer              | `string`                | 签发者                         |
| audience            | `string`                | 受众                           |

#### MemoryTokenStore

内存 Token 存储，实现 `TokenStore` 接口。

---

### Session 认证模块 (`@dreamer/auth/session`)

#### AuthSessionManager

Session 认证管理器类。

```typescript
class AuthSessionManager {
  constructor(options: AuthSessionOptions);
  login(ctx: HttpContext, user: AuthUser): Promise<void>;
  logout(ctx: HttpContext): Promise<void>;
  isAuthenticated(ctx: HttpContext): boolean;
  getUser(ctx: HttpContext): AuthUser | null;
  loadSession(ctx: HttpContext): Promise<boolean>;
  middleware(): (ctx: HttpContext, next: () => Promise<void>) => Promise<void>;
  requireAuth(redirectUrl?: string): (ctx: HttpContext, next: () => Promise<void>) => Promise<Response | void>;
}
```

**AuthSessionOptions**：

| 选项            | 类型                                  | 说明                          |
| --------------- | ------------------------------------- | ----------------------------- |
| store           | `SessionStore`                        | Session 存储适配器            |
| cookieName      | `string`                              | Cookie 名称（默认 authSessionId） |
| maxAge          | `number`                              | Session 过期时间（毫秒，默认 24h） |
| cookie          | `CookieOptions`                       | Cookie 选项                   |
| serializeUser   | `(user: AuthUser) => AuthUser`        | 用户序列化函数                |
| deserializeUser | `(user: AuthUser) => Promise<AuthUser \| null>` | 用户反序列化函数     |

---

### 权限验证 (`@dreamer/auth`)

#### 角色检查

| 函数                         | 说明                   |
| ---------------------------- | ---------------------- |
| `hasRole(user, role)`        | 检查是否有指定角色     |
| `hasAnyRole(user, roles)`    | 检查是否有任意角色     |
| `hasAllRoles(user, roles)`   | 检查是否有所有角色     |

#### 权限检查

| 函数                                  | 说明                   |
| ------------------------------------- | ---------------------- |
| `hasPermission(user, permission)`     | 检查是否有指定权限     |
| `hasAnyPermission(user, permissions)` | 检查是否有任意权限     |
| `hasAllPermissions(user, permissions)`| 检查是否有所有权限     |

#### 路径匹配

| 函数                           | 说明                     |
| ------------------------------ | ------------------------ |
| `matchPath(path, patterns)`    | 检查路径是否匹配模式     |
| `requiresAuth(path, options)`  | 检查路径是否需要认证     |
| `getRequiredRoles(path, roles)`| 获取路径所需的角色       |

---

## 📊 测试报告

| 指标         | Deno   | Bun    |
| ------------ | ------ | ------ |
| **总测试数** | 123    | 123    |
| **通过**     | 123    | 123    |
| **失败**     | 0      | 0      |
| **通过率**   | 100%   | 100%   |

详细测试报告请查看 [TEST_REPORT.md](./TEST_REPORT.md)。

---

## 📝 注意事项

- **密钥安全**：HMAC 算法密钥至少需要 32 字符，生产环境请使用强密钥
- **算法白名单**：验证 JWT 时建议指定允许的算法，防止算法混淆攻击
- **Token 存储**：生产环境 Refresh Token 应使用 Redis 等持久化存储
- **PKCE 推荐**：OAuth2 公开客户端（如 SPA、移动应用）建议使用 PKCE
- **Session 安全**：建议设置 `httpOnly`、`secure`、`sameSite` Cookie 选项

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

MIT License - 详见 [LICENSE.md](./LICENSE.md)

---

<div align="center">

**Made with ❤️ by Dreamer Team**

</div>
