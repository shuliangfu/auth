/**
 * @module @dreamer/auth
 *
 * 用户认证库
 *
 * 提供用户认证功能，支持：
 * - JWT 解析和验证
 * - Bearer Token 解析
 * - 基础认证（Basic Auth）
 * - 角色与权限验证
 * - 路由保护
 *
 * @example
 * ```typescript
 * import {
 *   parseBearerToken,
 *   parseBasicAuth,
 *   parseJwt,
 *   isJwtExpired,
 *   hasRole,
 *   hasPermission,
 * } from "@dreamer/auth";
 *
 * // 解析 Bearer Token
 * const token = parseBearerToken(request.headers.get("authorization"));
 *
 * // 解析 JWT
 * const payload = parseJwt(token);
 *
 * // 检查角色
 * if (hasRole(user, "admin")) {
 *   // ...
 * }
 * ```
 */

// ============================================================================
// 类型定义
// ============================================================================

/**
 * 用户信息接口
 */
export interface AuthUser {
  /** 用户 ID */
  id: string | number;
  /** 用户名 */
  username?: string;
  /** 邮箱 */
  email?: string;
  /** 角色列表 */
  roles?: string[];
  /** 权限列表 */
  permissions?: string[];
  /** 其他属性 */
  [key: string]: unknown;
}

/**
 * JWT 配置
 */
export interface JwtConfig {
  /** 密钥 */
  secret: string;
  /** 算法（默认 "HS256"） */
  algorithm?: "HS256" | "HS384" | "HS512";
  /** 过期时间（秒，默认 3600） */
  expiresIn?: number;
  /** 签发者 */
  issuer?: string;
  /** 受众 */
  audience?: string;
}

/**
 * JWT Payload
 */
export interface JwtPayload {
  /** 主体（用户 ID） */
  sub?: string;
  /** 签发者 */
  iss?: string;
  /** 受众 */
  aud?: string;
  /** 过期时间（Unix 时间戳） */
  exp?: number;
  /** 生效时间（Unix 时间戳） */
  nbf?: number;
  /** 签发时间（Unix 时间戳） */
  iat?: number;
  /** JWT ID */
  jti?: string;
  /** 其他自定义字段 */
  [key: string]: unknown;
}

/**
 * 认证选项
 */
export interface AuthOptions {
  /** 认证类型 */
  type?: "jwt" | "session" | "bearer" | "basic";
  /** JWT 配置 */
  jwt?: JwtConfig;
  /** 需要认证的路径 */
  protectedPaths?: string[] | RegExp[];
  /** 不需要认证的路径 */
  publicPaths?: string[] | RegExp[];
  /** 角色权限配置 */
  roles?: Record<string, string[]>;
}

// ============================================================================
// 路径匹配
// ============================================================================

/**
 * 检查路径是否匹配模式
 *
 * @param path - 请求路径
 * @param patterns - 匹配模式列表
 * @returns 是否匹配
 *
 * @example
 * ```typescript
 * matchPath("/api/users", ["/api/"]); // true
 * matchPath("/public", [/^\/public/]); // true
 * ```
 */
export function matchPath(
  path: string | undefined,
  patterns: string[] | RegExp[],
): boolean {
  if (!path || patterns.length === 0) return false;

  for (const pattern of patterns) {
    if (typeof pattern === "string") {
      if (path === pattern || path.startsWith(pattern)) {
        return true;
      }
    } else if (pattern instanceof RegExp) {
      if (pattern.test(path)) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// Token 解析
// ============================================================================

/**
 * 解析 Bearer Token
 *
 * @param authHeader - Authorization 头
 * @returns Token 或 null
 *
 * @example
 * ```typescript
 * const token = parseBearerToken("Bearer eyJhbGciOiJI...");
 * ```
 */
export function parseBearerToken(authHeader: string | null): string | null {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * 解析 Basic Auth
 *
 * @param authHeader - Authorization 头
 * @returns 用户名和密码或 null
 *
 * @example
 * ```typescript
 * const credentials = parseBasicAuth("Basic dXNlcjpwYXNz");
 * // { username: "user", password: "pass" }
 * ```
 */
export function parseBasicAuth(
  authHeader: string | null,
): { username: string; password: string } | null {
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return null;
  }

  try {
    const base64 = authHeader.slice(6);
    const decoded = atob(base64);
    const colonIndex = decoded.indexOf(":");
    if (colonIndex === -1) return null;

    return {
      username: decoded.slice(0, colonIndex),
      password: decoded.slice(colonIndex + 1),
    };
  } catch {
    return null;
  }
}

/**
 * 创建 Basic Auth 头
 *
 * @param username - 用户名
 * @param password - 密码
 * @returns Authorization 头值
 *
 * @example
 * ```typescript
 * const header = createBasicAuthHeader("user", "pass");
 * // "Basic dXNlcjpwYXNz"
 * ```
 */
export function createBasicAuthHeader(
  username: string,
  password: string,
): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

/**
 * 创建 Bearer Auth 头
 *
 * @param token - Token
 * @returns Authorization 头值
 *
 * @example
 * ```typescript
 * const header = createBearerAuthHeader("eyJhbGciOiJI...");
 * // "Bearer eyJhbGciOiJI..."
 * ```
 */
export function createBearerAuthHeader(token: string): string {
  return `Bearer ${token}`;
}

// ============================================================================
// JWT 解析
// ============================================================================

/**
 * 解析 JWT（不验证签名，仅提取 payload）
 *
 * 注意：生产环境应使用专业的 JWT 库进行签名验证
 *
 * @param token - JWT Token
 * @returns 解析后的 payload 或 null
 *
 * @example
 * ```typescript
 * const payload = parseJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.xxx");
 * // { sub: "12345" }
 * ```
 */
export function parseJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const payload = parts[1];
    // Base64URL 解码
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(base64);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * 检查 JWT 是否过期
 *
 * @param payload - JWT payload
 * @returns 是否过期
 *
 * @example
 * ```typescript
 * const payload = parseJwt(token);
 * if (isJwtExpired(payload)) {
 *   console.log("Token 已过期");
 * }
 * ```
 */
export function isJwtExpired(payload: JwtPayload | null): boolean {
  if (!payload) return true;
  const exp = payload.exp;
  if (!exp) return false;
  return Date.now() / 1000 > exp;
}

/**
 * 验证 JWT Claims
 *
 * @param payload - JWT payload
 * @param config - JWT 配置
 * @returns 验证结果
 *
 * @example
 * ```typescript
 * const result = validateJwtClaims(payload, {
 *   issuer: "my-app",
 *   audience: "my-api",
 * });
 * ```
 */
export function validateJwtClaims(
  payload: JwtPayload | null,
  config: JwtConfig,
): { valid: boolean; error?: string } {
  if (!payload) {
    return { valid: false, error: "无效的 JWT payload" };
  }

  // 检查过期
  if (isJwtExpired(payload)) {
    return { valid: false, error: "JWT 已过期" };
  }

  // 检查签发者
  if (config.issuer && payload.iss !== config.issuer) {
    return { valid: false, error: "签发者不匹配" };
  }

  // 检查受众
  if (config.audience && payload.aud !== config.audience) {
    return { valid: false, error: "受众不匹配" };
  }

  // 检查生效时间
  if (payload.nbf && Date.now() / 1000 < payload.nbf) {
    return { valid: false, error: "JWT 尚未生效" };
  }

  return { valid: true };
}

/**
 * 从 JWT payload 提取用户信息
 *
 * @param payload - JWT payload
 * @returns 用户信息
 *
 * @example
 * ```typescript
 * const payload = parseJwt(token);
 * const user = extractUserFromJwt(payload);
 * ```
 */
export function extractUserFromJwt(
  payload: JwtPayload | null,
): AuthUser | null {
  if (!payload) return null;

  return {
    id: payload.sub || (payload.id as string) || "",
    username: payload.username as string,
    email: payload.email as string,
    roles: payload.roles as string[],
    permissions: payload.permissions as string[],
    ...payload,
  };
}

// ============================================================================
// 角色权限检查
// ============================================================================

/**
 * 检查用户是否拥有指定角色
 *
 * @param user - 用户信息
 * @param role - 角色名
 * @returns 是否拥有角色
 *
 * @example
 * ```typescript
 * if (hasRole(user, "admin")) {
 *   // 管理员操作
 * }
 * ```
 */
export function hasRole(user: AuthUser | null, role: string): boolean {
  if (!user || !user.roles) return false;
  return user.roles.includes(role);
}

/**
 * 检查用户是否拥有任意指定角色
 *
 * @param user - 用户信息
 * @param roles - 角色列表
 * @returns 是否拥有任意角色
 *
 * @example
 * ```typescript
 * if (hasAnyRole(user, ["admin", "moderator"])) {
 *   // 管理操作
 * }
 * ```
 */
export function hasAnyRole(user: AuthUser | null, roles: string[]): boolean {
  if (!user || !user.roles) return false;
  return roles.some((role) => user.roles!.includes(role));
}

/**
 * 检查用户是否拥有所有指定角色
 *
 * @param user - 用户信息
 * @param roles - 角色列表
 * @returns 是否拥有所有角色
 *
 * @example
 * ```typescript
 * if (hasAllRoles(user, ["admin", "verified"])) {
 *   // 需要同时拥有两个角色
 * }
 * ```
 */
export function hasAllRoles(user: AuthUser | null, roles: string[]): boolean {
  if (!user || !user.roles) return false;
  return roles.every((role) => user.roles!.includes(role));
}

/**
 * 检查用户是否拥有指定权限
 *
 * @param user - 用户信息
 * @param permission - 权限名
 * @returns 是否拥有权限
 *
 * @example
 * ```typescript
 * if (hasPermission(user, "users:write")) {
 *   // 有写入权限
 * }
 * ```
 */
export function hasPermission(
  user: AuthUser | null,
  permission: string,
): boolean {
  if (!user || !user.permissions) return false;
  return user.permissions.includes(permission);
}

/**
 * 检查用户是否拥有任意指定权限
 *
 * @param user - 用户信息
 * @param permissions - 权限列表
 * @returns 是否拥有任意权限
 *
 * @example
 * ```typescript
 * if (hasAnyPermission(user, ["users:read", "users:write"])) {
 *   // 有用户相关权限
 * }
 * ```
 */
export function hasAnyPermission(
  user: AuthUser | null,
  permissions: string[],
): boolean {
  if (!user || !user.permissions) return false;
  return permissions.some((p) => user.permissions!.includes(p));
}

/**
 * 检查用户是否拥有所有指定权限
 *
 * @param user - 用户信息
 * @param permissions - 权限列表
 * @returns 是否拥有所有权限
 *
 * @example
 * ```typescript
 * if (hasAllPermissions(user, ["users:read", "users:write"])) {
 *   // 有完整的用户读写权限
 * }
 * ```
 */
export function hasAllPermissions(
  user: AuthUser | null,
  permissions: string[],
): boolean {
  if (!user || !user.permissions) return false;
  return permissions.every((p) => user.permissions!.includes(p));
}

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 检查路径是否需要认证
 *
 * @param path - 请求路径
 * @param options - 认证选项
 * @returns 是否需要认证
 */
export function requiresAuth(path: string, options: AuthOptions): boolean {
  // 如果在公开路径中，不需要认证
  if (options.publicPaths && matchPath(path, options.publicPaths)) {
    return false;
  }

  // 如果配置了保护路径，检查是否匹配
  if (options.protectedPaths && options.protectedPaths.length > 0) {
    return matchPath(path, options.protectedPaths);
  }

  // 默认需要认证
  return true;
}

/**
 * 获取路径所需的角色
 *
 * @param path - 请求路径
 * @param roles - 角色配置
 * @returns 所需角色列表
 */
export function getRequiredRoles(
  path: string,
  roles: Record<string, string[]>,
): string[] {
  // 精确匹配
  if (roles[path]) {
    return roles[path];
  }

  // 前缀匹配
  for (const [pattern, requiredRoles] of Object.entries(roles)) {
    if (path.startsWith(pattern)) {
      return requiredRoles;
    }
  }

  return [];
}

// ============================================================================
// JWT 签名和验证（基于 @dreamer/crypto）
// ============================================================================

export {
  type DecodedToken,
  decodeToken,
  generateECKeyPair,
  generateRSAKeyPair,
  getTokenExpiration,
  getTokenRemainingTime,
  isTokenExpired,
  type JwtAlgorithm,
  type KeyPair,
  signToken,
  type SignTokenOptions,
  verifyToken,
  type VerifyTokenOptions,
} from "./jwt.ts";

// ============================================================================
// Session 认证（基于 @dreamer/session）
// ============================================================================

export {
  type AuthSessionData,
  AuthSessionManager,
  type AuthSessionOptions,
  type CookieOptions,
  createAuthSession,
  type HttpContext,
  type SessionStore,
} from "./session.ts";

// ============================================================================
// 刷新 Token 机制
// ============================================================================

export {
  createTokenManager,
  type GenerateTokenOptions,
  MemoryTokenStore,
  type RefreshTokenData,
  TokenManager,
  type TokenManagerOptions,
  type TokenPair,
  type TokenStore,
} from "./refresh.ts";

// ============================================================================
// OAuth2 认证
// ============================================================================

export {
  type AuthorizationUrlOptions,
  createGitHubClient,
  createGoogleClient,
  createOAuth2Client,
  DingTalkProvider,
  type ExchangeCodeOptions,
  generatePKCE,
  generateState,
  GiteeProvider,
  // 内置 Provider
  GitHubProvider,
  GitLabProvider,
  GoogleProvider,
  OAuth2Client,
  // 类型
  type OAuth2Config,
  type OAuth2TokenResponse,
  type OAuth2UserInfo,
  parseGiteeUser,
  // 用户信息解析器
  parseGitHubUser,
  parseGitLabUser,
  parseGoogleUser,
  parseWeChatUser,
  type PKCEParams,
  WeChatProvider,
  WeComProvider,
} from "./oauth.ts";
