# @dreamer/auth 示例

本目录包含 `@dreamer/auth` 库的使用示例。

## 示例列表

| 文件 | 说明 |
|------|------|
| [jwt.ts](./jwt.ts) | JWT 签名、验证、解码，支持 HS256/RS256/ES256 |
| [session.ts](./session.ts) | Session 会话管理：登录、登出、持久化 |
| [oauth.ts](./oauth.ts) | OAuth2 认证流程：GitHub、Google、微信 |
| [permission.ts](./permission.ts) | 权限验证：角色、权限检查 |
| [refresh-token.ts](./refresh-token.ts) | Token 刷新机制：刷新、撤销、黑名单 |

## 运行示例

```bash
# 运行 JWT 示例
deno run -A examples/jwt.ts

# 运行 Session 示例
deno run -A examples/session.ts

# 运行 OAuth2 示例
deno run -A examples/oauth.ts

# 运行权限验证示例
deno run -A examples/permission.ts

# 运行 Refresh Token 示例
deno run -A examples/refresh-token.ts
```

## 功能概览

### JWT 功能

- 支持 HMAC（HS256/HS384/HS512）
- 支持 RSA（RS256/RS384/RS512）
- 支持 ECDSA（ES256/ES384/ES512）
- Token 解码、过期检查
- 密钥对生成

### Session 管理

- 内存存储（可扩展 Redis）
- Cookie 配置
- 自定义序列化/反序列化
- 登录/登出/加载

### OAuth2 支持

- Authorization Code 流程
- PKCE 支持（移动端/SPA）
- State 防 CSRF
- 支持各种 OAuth2 提供商

### 权限验证

- 角色检查：`hasRole`、`hasAnyRole`、`hasAllRoles`
- 权限检查：`hasPermission`、`hasAnyPermission`、`hasAllPermissions`
- 认证守卫：`createAuthGuard`

### Token 刷新

- Access Token + Refresh Token 双 Token
- Token 刷新、撤销
- 用户所有 Token 撤销
- 过期检查、刷新建议
