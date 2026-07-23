# @dreamer/auth 测试报告

## 📊 测试概览

| 项目           | 值                              |
| -------------- | ------------------------------- |
| **测试包版本** | `@dreamer/auth@1.1.0`          |
| **加密包版本** | `@dreamer/crypto@^1.1.0`       |
| **会话包版本** | `@dreamer/session@^1.1.0`      |
| **测试框架**   | `@dreamer/test@^1.2.3`         |
| **测试时间**   | `2026-07-23`                    |
| **测试环境**   | Deno 2.9+, Bun 1.3+, Node.js 22+ |

---

## 🎯 测试结果

### 总体统计

| 指标         | Deno | Bun   | Node.js |
| ------------ | ---- | ----- | ------- |
| **总测试数** | 128  | 123   | 123     |
| **通过**     | 128  | 123   | 123     |
| **失败**     | 0    | 0     | 0       |
| **通过率**   | 100% | 100%  | 100%    |
| **执行时间** | ~6s  | ~4.6s | ~5s     |

> Deno 在 123 个单元测试之上额外计入 5 个生命周期钩子（`describe` `afterAll` +
> `@dreamer/test` 清理）；Bun 与 Node.js 报告 123 个单元测试。

### 测试文件统计

| 测试文件          | 测试数 | 通过 | 失败 | 状态    |
| ----------------- | ------ | ---- | ---- | ------- |
| `jwt.test.ts`     | 22     | 22   | 0    | ✅ 通过 |
| `mod.test.ts`     | 45     | 45   | 0    | ✅ 通过 |
| `oauth.test.ts`   | 22     | 22   | 0    | ✅ 通过 |
| `refresh.test.ts` | 15     | 15   | 0    | ✅ 通过 |
| `session.test.ts` | 24     | 24   | 0    | ✅ 通过 |

---

## 📋 功能测试详情

### 1. JWT 签名与验证 (jwt.test.ts) - 22 个测试

#### signToken - JWT 签名 (3 个测试)

| 测试场景                   | 状态 |
| -------------------------- | ---- |
| 应该使用 HS256 签名 JWT    | ✅   |
| 应该包含正确的 payload     | ✅   |
| 应该支持不同的过期时间格式 | ✅   |

#### verifyToken - JWT 验证 (4 个测试)

| 测试场景             | 状态 |
| -------------------- | ---- |
| 应该验证有效的 JWT   | ✅   |
| 应该拒绝错误的密钥   | ✅   |
| 应该拒绝过期的 Token | ✅   |
| 应该验证签发者       | ✅   |

#### decodeToken - JWT 解码 (2 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该解码 JWT Header 和 Payload | ✅   |
| 应该抛出无效 Token 格式错误    | ✅   |

#### isTokenExpired - 过期检查 (3 个测试)

| 测试场景                          | 状态 |
| --------------------------------- | ---- |
| 应该返回 false 对于未过期的 Token | ✅   |
| 应该返回 true 对于过期的 Token    | ✅   |
| 应该返回 true 对于无效的 Token    | ✅   |

#### getTokenExpiration - 获取过期时间 (2 个测试)

| 测试场景                             | 状态 |
| ------------------------------------ | ---- |
| 应该返回过期时间戳                   | ✅   |
| 应该返回 null 对于无过期时间的 Token | ✅   |

#### getTokenRemainingTime - 获取剩余时间 (3 个测试)

| 测试场景                           | 状态 |
| ---------------------------------- | ---- |
| 应该返回正确的剩余时间             | ✅   |
| 应该返回 0 对于过期的 Token        | ✅   |
| 应该返回 -1 对于无过期时间的 Token | ✅   |

#### generateRSAKeyPair - RSA 密钥对生成 (2 个测试)

| 测试场景                    | 状态 |
| --------------------------- | ---- |
| 应该生成 RSA 密钥对         | ✅   |
| 应该使用 RSA 密钥签名和验证 | ✅   |

#### generateECKeyPair - ECDSA 密钥对生成 (2 个测试)

| 测试场景                      | 状态 |
| ----------------------------- | ---- |
| 应该生成 ECDSA 密钥对         | ✅   |
| 应该使用 ECDSA 密钥签名和验证 | ✅   |

---

### 2. 认证工具函数 (mod.test.ts) - 45 个测试

#### parseBearerToken - Bearer Token 解析 (4 个测试)

| 测试场景                         | 状态 |
| -------------------------------- | ---- |
| 应该解析有效的 Bearer Token      | ✅   |
| 应该返回 null 对于 null 输入     | ✅   |
| 应该返回 null 对于非 Bearer 前缀 | ✅   |
| 应该返回 null 对于空字符串       | ✅   |

#### parseBasicAuth - Basic Auth 解析 (3 个测试)

| 测试场景                   | 状态 |
| -------------------------- | ---- |
| 应该解析有效的 Basic Auth  | ✅   |
| 应该处理包含冒号的密码     | ✅   |
| 应该返回 null 对于无效输入 | ✅   |

#### createBasicAuthHeader - Basic Auth 头生成 (1 个测试)

| 测试场景                     | 状态 |
| ---------------------------- | ---- |
| 应该生成正确的 Basic Auth 头 | ✅   |

#### createBearerAuthHeader - Bearer Auth 头生成 (1 个测试)

| 测试场景                      | 状态 |
| ----------------------------- | ---- |
| 应该生成正确的 Bearer Auth 头 | ✅   |

#### parseJwt - JWT 解析 (2 个测试)

| 测试场景                     | 状态 |
| ---------------------------- | ---- |
| 应该解析有效的 JWT           | ✅   |
| 应该返回 null 对于无效 Token | ✅   |

#### isJwtExpired - JWT 过期检查 (4 个测试)

| 测试场景                                  | 状态 |
| ----------------------------------------- | ---- |
| 应该返回 true 对于 null payload           | ✅   |
| 应该返回 false 对于没有过期时间的 payload | ✅   |
| 应该返回 true 对于已过期的 payload        | ✅   |
| 应该返回 false 对于未过期的 payload       | ✅   |

#### validateJwtClaims - JWT Claims 验证 (3 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该验证通过对于有效的 payload | ✅   |
| 应该验证失败对于过期的 payload | ✅   |
| 应该验证失败对于签发者不匹配   | ✅   |

#### extractUserFromJwt - 从 JWT 提取用户 (2 个测试)

| 测试场景                        | 状态 |
| ------------------------------- | ---- |
| 应该提取用户信息                | ✅   |
| 应该返回 null 对于 null payload | ✅   |

#### 角色检查 - hasRole (3 个测试)

| 测试场景                        | 状态 |
| ------------------------------- | ---- |
| 应该返回 true 如果用户有角色    | ✅   |
| 应该返回 false 如果用户没有角色 | ✅   |
| 应该返回 false 对于 null 用户   | ✅   |

#### 角色检查 - hasAnyRole (2 个测试)

| 测试场景                            | 状态 |
| ----------------------------------- | ---- |
| 应该返回 true 如果用户有任意角色    | ✅   |
| 应该返回 false 如果用户没有任何角色 | ✅   |

#### 角色检查 - hasAllRoles (2 个测试)

| 测试场景                            | 状态 |
| ----------------------------------- | ---- |
| 应该返回 true 如果用户有所有角色    | ✅   |
| 应该返回 false 如果用户缺少任何角色 | ✅   |

#### 权限检查 - hasPermission (2 个测试)

| 测试场景                        | 状态 |
| ------------------------------- | ---- |
| 应该返回 true 如果用户有权限    | ✅   |
| 应该返回 false 如果用户没有权限 | ✅   |

#### 权限检查 - hasAnyPermission (2 个测试)

| 测试场景                            | 状态 |
| ----------------------------------- | ---- |
| 应该返回 true 如果用户有任意权限    | ✅   |
| 应该返回 false 如果用户没有任何权限 | ✅   |

#### 权限检查 - hasAllPermissions (2 个测试)

| 测试场景                            | 状态 |
| ----------------------------------- | ---- |
| 应该返回 true 如果用户有所有权限    | ✅   |
| 应该返回 false 如果用户缺少任何权限 | ✅   |

#### matchPath - 路径匹配 (5 个测试)

| 测试场景                           | 状态 |
| ---------------------------------- | ---- |
| 应该匹配精确路径                   | ✅   |
| 应该匹配前缀路径                   | ✅   |
| 应该匹配正则表达式                 | ✅   |
| 应该返回 false 对于不匹配的路径    | ✅   |
| 应该返回 false 对于 undefined 路径 | ✅   |

#### requiresAuth - 认证需求检查 (3 个测试)

| 测试场景                     | 状态 |
| ---------------------------- | ---- |
| 应该返回 false 对于公开路径  | ✅   |
| 应该返回 true 对于受保护路径 | ✅   |
| 应该返回 true 默认情况       | ✅   |

#### getRequiredRoles - 获取所需角色 (3 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该返回精确匹配的角色         | ✅   |
| 应该返回前缀匹配的角色         | ✅   |
| 应该返回空数组对于不匹配的路径 | ✅   |

---

### 3. OAuth 2.0 客户端 (oauth.test.ts) - 22 个测试

#### generatePKCE - PKCE 参数生成 (2 个测试)

| 测试场景                                 | 状态 |
| ---------------------------------------- | ---- |
| 应该生成 code_verifier 和 code_challenge | ✅   |
| 应该每次生成不同的 PKCE 参数             | ✅   |

#### generateState - 状态参数生成 (2 个测试)

| 测试场景               | 状态 |
| ---------------------- | ---- |
| 应该生成随机状态字符串 | ✅   |
| 应该每次生成不同的状态 | ✅   |

#### OAuth2Client - 客户端 (5 个测试)

| 测试场景             | 状态 |
| -------------------- | ---- |
| 应该生成授权 URL     | ✅   |
| 应该支持自定义 scope | ✅   |
| 应该支持 state 参数  | ✅   |
| 应该支持 PKCE        | ✅   |
| 应该支持额外参数     | ✅   |

#### 内置 Provider 配置 (5 个测试)

| 测试场景                         | 状态 |
| -------------------------------- | ---- |
| GitHub Provider 应该有正确的端点 | ✅   |
| Google Provider 应该有正确的端点 | ✅   |
| WeChat Provider 应该有正确的端点 | ✅   |
| GitLab Provider 应该有正确的端点 | ✅   |
| Gitee Provider 应该有正确的端点  | ✅   |

#### 用户信息解析器 (4 个测试)

| 测试场景                     | 状态 |
| ---------------------------- | ---- |
| parseGitHubUser 应该正确解析 | ✅   |
| parseGoogleUser 应该正确解析 | ✅   |
| parseGitLabUser 应该正确解析 | ✅   |
| parseGiteeUser 应该正确解析  | ✅   |

#### 工厂函数 (3 个测试)

| 测试场景                                  | 状态 |
| ----------------------------------------- | ---- |
| createOAuth2Client 应该创建客户端         | ✅   |
| createGitHubClient 应该创建 GitHub 客户端 | ✅   |
| createGoogleClient 应该创建 Google 客户端 | ✅   |

---

### 4. Token 刷新管理 (refresh.test.ts) - 15 个测试

#### MemoryTokenStore - 内存存储 (5 个测试)

| 测试场景                         | 状态 |
| -------------------------------- | ---- |
| 应该保存和获取 Token             | ✅   |
| 应该返回 null 对于不存在的 Token | ✅   |
| 应该删除 Token                   | ✅   |
| 应该按用户删除所有 Token         | ✅   |
| 应该返回 null 对于过期的 Token   | ✅   |

#### TokenManager - Token 管理器 (8 个测试)

| 测试场景                           | 状态 |
| ---------------------------------- | ---- |
| 应该生成 Token 对                  | ✅   |
| 应该验证 Access Token              | ✅   |
| 应该刷新 Token                     | ✅   |
| 应该拒绝使用已刷新的 Refresh Token | ✅   |
| 应该撤销 Refresh Token             | ✅   |
| 应该撤销用户的所有 Token           | ✅   |
| 应该检查 Token 是否需要刷新        | ✅   |
| 应该检查 Token 是否过期            | ✅   |

#### createTokenManager - 工厂函数 (1 个测试)

| 测试场景                   | 状态 |
| -------------------------- | ---- |
| 应该创建 TokenManager 实例 | ✅   |

---

### 5. 认证会话管理 (session.test.ts) - 24 个测试

#### AuthSessionManager - login 登录 (2 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该创建 Session 并设置 Cookie | ✅   |
| 应该将 Session 存储到 store    | ✅   |

#### AuthSessionManager - logout 登出 (2 个测试)

| 测试场景                   | 状态 |
| -------------------------- | ---- |
| 应该删除 Session 和 Cookie | ✅   |
| 应该处理未登录的情况       | ✅   |

#### AuthSessionManager - isAuthenticated 认证检查 (3 个测试)

| 测试场景                        | 状态 |
| ------------------------------- | ---- |
| 应该返回 true 对于已登录用户    | ✅   |
| 应该返回 false 对于未登录用户   | ✅   |
| 应该返回 false 对于登出后的用户 | ✅   |

#### AuthSessionManager - getUser 获取用户 (2 个测试)

| 测试场景                     | 状态 |
| ---------------------------- | ---- |
| 应该返回已登录用户信息       | ✅   |
| 应该返回 null 对于未登录用户 | ✅   |

#### AuthSessionManager - loadSession 加载 Session (4 个测试)

| 测试场景                                      | 状态 |
| --------------------------------------------- | ---- |
| 应该从 Cookie 加载 Session                    | ✅   |
| 应该返回 false 对于无 Cookie 的请求           | ✅   |
| 应该返回 false 并清除 Cookie 对于无效 Session | ✅   |
| 应该更新最后活动时间                          | ✅   |

#### AuthSessionManager - middleware 中间件 (2 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该自动加载 Session           | ✅   |
| 应该在无 Session 时也调用 next | ✅   |

#### AuthSessionManager - requireAuth 认证保护中间件 (3 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该允许已认证用户通过         | ✅   |
| 应该返回 401 对于未认证用户    | ✅   |
| 应该重定向未认证用户到指定 URL | ✅   |

#### createAuthSession - 工厂函数 (2 个测试)

| 测试场景                         | 状态 |
| -------------------------------- | ---- |
| 应该创建 AuthSessionManager 实例 | ✅   |
| 应该使用自定义配置               | ✅   |

#### 用户序列化 (3 个测试)

| 测试场景                       | 状态 |
| ------------------------------ | ---- |
| 应该支持自定义序列化函数       | ✅   |
| 应该支持自定义反序列化函数     | ✅   |
| 应该在用户不存在时删除 Session | ✅   |

---

## 📈 测试覆盖分析

### 接口方法覆盖

| 模块         | 方法/功能                | 覆盖状态 |
| ------------ | ------------------------ | -------- |
| `jwt.ts`     | `signToken`              | ✅       |
| `jwt.ts`     | `verifyToken`            | ✅       |
| `jwt.ts`     | `decodeToken`            | ✅       |
| `jwt.ts`     | `isTokenExpired`         | ✅       |
| `jwt.ts`     | `getTokenExpiration`     | ✅       |
| `jwt.ts`     | `getTokenRemainingTime`  | ✅       |
| `jwt.ts`     | `generateRSAKeyPair`     | ✅       |
| `jwt.ts`     | `generateECKeyPair`      | ✅       |
| `mod.ts`     | `parseBearerToken`       | ✅       |
| `mod.ts`     | `parseBasicAuth`         | ✅       |
| `mod.ts`     | `createBasicAuthHeader`  | ✅       |
| `mod.ts`     | `createBearerAuthHeader` | ✅       |
| `mod.ts`     | `parseJwt`               | ✅       |
| `mod.ts`     | `isJwtExpired`           | ✅       |
| `mod.ts`     | `validateJwtClaims`      | ✅       |
| `mod.ts`     | `extractUserFromJwt`     | ✅       |
| `mod.ts`     | `hasRole`                | ✅       |
| `mod.ts`     | `hasAnyRole`             | ✅       |
| `mod.ts`     | `hasAllRoles`            | ✅       |
| `mod.ts`     | `hasPermission`          | ✅       |
| `mod.ts`     | `hasAnyPermission`       | ✅       |
| `mod.ts`     | `hasAllPermissions`      | ✅       |
| `mod.ts`     | `matchPath`              | ✅       |
| `mod.ts`     | `requiresAuth`           | ✅       |
| `mod.ts`     | `getRequiredRoles`       | ✅       |
| `oauth.ts`   | `generatePKCE`           | ✅       |
| `oauth.ts`   | `generateState`          | ✅       |
| `oauth.ts`   | `OAuth2Client`           | ✅       |
| `oauth.ts`   | `createOAuth2Client`     | ✅       |
| `oauth.ts`   | `createGitHubClient`     | ✅       |
| `oauth.ts`   | `createGoogleClient`     | ✅       |
| `refresh.ts` | `MemoryTokenStore`       | ✅       |
| `refresh.ts` | `TokenManager`           | ✅       |
| `refresh.ts` | `createTokenManager`     | ✅       |
| `session.ts` | `AuthSessionManager`     | ✅       |
| `session.ts` | `createAuthSession`      | ✅       |

### 边界情况覆盖

| 场景                | 覆盖状态 |
| ------------------- | -------- |
| null/undefined 输入 | ✅       |
| 空字符串处理        | ✅       |
| 无效 Token 格式     | ✅       |
| 过期 Token 处理     | ✅       |
| 错误密钥验证        | ✅       |
| 不存在的 Session    | ✅       |
| 用户无角色/权限     | ✅       |
| 路径不匹配          | ✅       |

### 错误处理覆盖

| 场景                      | 覆盖状态 |
| ------------------------- | -------- |
| 无效 Token 抛出错误       | ✅       |
| 验证失败返回 null         | ✅       |
| 过期 Token 拒绝           | ✅       |
| 已使用 Refresh Token 拒绝 | ✅       |
| 未认证用户返回 401        | ✅       |
| 签发者不匹配验证失败      | ✅       |

---

## ✨ 优点

1. **完整的 JWT 支持**：支持 HS256、RS256、ES256
   等多种算法，提供签名、验证、解码等完整功能
2. **灵活的 OAuth 2.0**：内置 GitHub、Google、WeChat、GitLab、Gitee 等多种
   Provider，支持 PKCE
3. **Token 刷新机制**：提供 Access Token + Refresh Token 的双 Token 机制，支持
   Token 撤销
4. **会话管理集成**：与 `@dreamer/session`
   深度集成，提供登录、登出、认证检查等功能
5. **权限验证**：支持角色、权限检查，支持路径匹配和认证需求配置
6. **跨运行时兼容**：完全兼容 Deno 2.9+、Bun 1.3+ 与 Node.js 22+。

---

## 📝 结论

@dreamer/auth 的 123 个单元测试在 Deno 2.9+、Bun 1.3+ 与 Node.js 22+ 上全部通过，
覆盖了 JWT 签名验证、OAuth 2.0 客户端、Token 刷新管理、认证会话管理和权限验证等核心功能。
包提供了完整的认证解决方案，支持多种认证方式和 OAuth Provider，并通过三运行时测试验证了跨平台兼容性。

---

<div align="center">

**测试通过率：100%** ✅

_123 个单元测试 | Deno 128（含生命周期） | Bun 123 | Node.js 123_

</div>
