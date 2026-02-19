/**
 * @module @dreamer/auth/refresh
 *
 * 刷新 Token 机制模块
 *
 * 提供 Access Token + Refresh Token 双令牌机制，包括：
 * - Access Token 生成（短期有效）
 * - Refresh Token 生成（长期有效）
 * - Token 刷新
 * - Token 撤销
 *
 * @example
 * ```typescript
 * import { TokenManager } from "@dreamer/auth/refresh";
 *
 * const tokenManager = new TokenManager({
 *   accessTokenSecret: "access-secret",
 *   refreshTokenSecret: "refresh-secret",
 *   accessTokenExpiry: "15m",
 *   refreshTokenExpiry: "7d",
 * });
 *
 * // 生成令牌对
 * const tokens = await tokenManager.generateTokenPair({ userId: "123" });
 *
 * // 刷新令牌
 * const newTokens = await tokenManager.refresh(tokens.refreshToken);
 * ```
 */

import { decodeToken, isTokenExpired, signToken, verifyToken } from "./jwt.ts";
import type { JWTPayload } from "./jwt.ts";
import { $tr } from "./i18n.ts";

// ============================================================================
// 类型定义
// ============================================================================

/**
 * Token 对
 */
export interface TokenPair {
  /** Access Token（短期有效） */
  accessToken: string;
  /** Refresh Token（长期有效） */
  refreshToken: string;
  /** Access Token 过期时间（Unix 时间戳，秒） */
  accessTokenExpiresAt: number;
  /** Refresh Token 过期时间（Unix 时间戳，秒） */
  refreshTokenExpiresAt: number;
}

/**
 * Token 存储接口（用于 Refresh Token 持久化）
 */
export interface TokenStore {
  /** 保存 Refresh Token */
  save(tokenId: string, data: RefreshTokenData): Promise<void>;
  /** 获取 Refresh Token 数据 */
  get(tokenId: string): Promise<RefreshTokenData | null>;
  /** 删除 Refresh Token */
  delete(tokenId: string): Promise<void>;
  /** 删除用户的所有 Refresh Token */
  deleteByUser(userId: string): Promise<void>;
}

/**
 * Refresh Token 存储数据
 */
export interface RefreshTokenData {
  /** Token ID */
  tokenId: string;
  /** 用户 ID */
  userId: string;
  /** 过期时间（Unix 时间戳） */
  expiresAt: number;
  /** 创建时间 */
  createdAt: number;
  /** 设备信息（可选） */
  device?: string;
  /** IP 地址（可选） */
  ip?: string;
  /** 是否已撤销 */
  revoked?: boolean;
}

/**
 * Token Manager 配置选项
 */
export interface TokenManagerOptions {
  /** Access Token 密钥 */
  accessTokenSecret: string | CryptoKey;
  /** Refresh Token 密钥 */
  refreshTokenSecret: string | CryptoKey;
  /** Access Token 过期时间（默认 "15m"） */
  accessTokenExpiry?: string;
  /** Refresh Token 过期时间（默认 "7d"） */
  refreshTokenExpiry?: string;
  /** Token 存储（用于持久化 Refresh Token） */
  store?: TokenStore;
  /** 签发者 */
  issuer?: string;
  /** 受众 */
  audience?: string;
}

/**
 * 生成 Token 选项
 */
export interface GenerateTokenOptions {
  /** 设备信息 */
  device?: string;
  /** IP 地址 */
  ip?: string;
}

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 生成随机 Token ID
 */
function generateTokenId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 解析时间字符串为秒数
 */
function parseTimeString(timeStr: string): number {
  const match = timeStr.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error($tr("auth.refresh.invalidTimeFormat", { timeStr }));
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 60 * 60;
    case "d":
      return value * 24 * 60 * 60;
    default:
      throw new Error($tr("auth.refresh.unsupportedTimeUnit", { unit }));
  }
}

// ============================================================================
// 内存存储（默认实现）
// ============================================================================

/**
 * 内存 Token 存储
 *
 * 注意：仅用于开发和测试，生产环境应使用 Redis 等持久化存储
 */
export class MemoryTokenStore implements TokenStore {
  /** Token 存储 */
  private tokens: Map<string, RefreshTokenData> = new Map();

  /**
   * 保存 Refresh Token
   */
  async save(tokenId: string, data: RefreshTokenData): Promise<void> {
    await Promise.resolve();
    this.tokens.set(tokenId, data);
  }

  /**
   * 获取 Refresh Token 数据
   */
  async get(tokenId: string): Promise<RefreshTokenData | null> {
    await Promise.resolve();
    const data = this.tokens.get(tokenId);
    if (!data) return null;

    // 检查是否过期
    if (data.expiresAt < Math.floor(Date.now() / 1000)) {
      this.tokens.delete(tokenId);
      return null;
    }

    return data;
  }

  /**
   * 删除 Refresh Token
   */
  async delete(tokenId: string): Promise<void> {
    await Promise.resolve();
    this.tokens.delete(tokenId);
  }

  /**
   * 删除用户的所有 Refresh Token
   */
  async deleteByUser(userId: string): Promise<void> {
    await Promise.resolve();
    for (const [tokenId, data] of this.tokens.entries()) {
      if (data.userId === userId) {
        this.tokens.delete(tokenId);
      }
    }
  }

  /**
   * 清理过期 Token
   */
  cleanup(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [tokenId, data] of this.tokens.entries()) {
      if (data.expiresAt < now) {
        this.tokens.delete(tokenId);
      }
    }
  }
}

// ============================================================================
// Token Manager
// ============================================================================

/**
 * Token 管理器
 *
 * 实现 Access Token + Refresh Token 双令牌机制
 */
export class TokenManager {
  /** Access Token 密钥 */
  private accessTokenSecret: string | CryptoKey;
  /** Refresh Token 密钥 */
  private refreshTokenSecret: string | CryptoKey;
  /** Access Token 过期时间（秒） */
  private accessTokenExpiry: number;
  /** Refresh Token 过期时间（秒） */
  private refreshTokenExpiry: number;
  /** Access Token 过期时间字符串 */
  private accessTokenExpiryStr: string;
  /** Refresh Token 过期时间字符串 */
  private refreshTokenExpiryStr: string;
  /** Token 存储 */
  private store: TokenStore;
  /** 签发者 */
  private issuer?: string;
  /** 受众 */
  private audience?: string;

  /**
   * 创建 TokenManager 实例
   *
   * @param options - 配置选项
   */
  constructor(options: TokenManagerOptions) {
    this.accessTokenSecret = options.accessTokenSecret;
    this.refreshTokenSecret = options.refreshTokenSecret;
    this.accessTokenExpiryStr = options.accessTokenExpiry || "15m";
    this.refreshTokenExpiryStr = options.refreshTokenExpiry || "7d";
    this.accessTokenExpiry = parseTimeString(this.accessTokenExpiryStr);
    this.refreshTokenExpiry = parseTimeString(this.refreshTokenExpiryStr);
    this.store = options.store || new MemoryTokenStore();
    this.issuer = options.issuer;
    this.audience = options.audience;
  }

  /**
   * 生成令牌对
   *
   * @param payload - Token 载荷（必须包含 userId 或 sub）
   * @param options - 生成选项
   * @returns Token 对
   *
   * @example
   * ```typescript
   * const tokens = await tokenManager.generateTokenPair({
   *   userId: "123",
   *   username: "admin",
   *   roles: ["admin"],
   * });
   * ```
   */
  async generateTokenPair(
    payload: Record<string, unknown>,
    options: GenerateTokenOptions = {},
  ): Promise<TokenPair> {
    const now = Math.floor(Date.now() / 1000);
    const tokenId = generateTokenId();
    const userId = (payload.userId || payload.sub || "") as string;

    // 生成 Access Token
    const accessToken = await signToken(
      { ...payload, type: "access" },
      this.accessTokenSecret,
      {
        expiresIn: this.accessTokenExpiryStr,
        issuer: this.issuer,
        audience: this.audience,
      },
    );

    // 生成 Refresh Token
    const refreshToken = await signToken(
      { sub: userId, jti: tokenId, type: "refresh" },
      this.refreshTokenSecret,
      {
        expiresIn: this.refreshTokenExpiryStr,
        issuer: this.issuer,
        audience: this.audience,
      },
    );

    // 保存 Refresh Token 到存储
    await this.store.save(tokenId, {
      tokenId,
      userId,
      expiresAt: now + this.refreshTokenExpiry,
      createdAt: now,
      device: options.device,
      ip: options.ip,
    });

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: now + this.accessTokenExpiry,
      refreshTokenExpiresAt: now + this.refreshTokenExpiry,
    };
  }

  /**
   * 刷新令牌
   *
   * @param refreshToken - Refresh Token
   * @param newPayload - 新的载荷数据（可选，用于更新用户信息）
   * @returns 新的 Token 对
   * @throws 如果 Refresh Token 无效或已过期
   *
   * @example
   * ```typescript
   * try {
   *   const newTokens = await tokenManager.refresh(refreshToken);
   *   console.log(newTokens.accessToken);
   * } catch (error) {
   *   console.error("刷新失败:", error.message);
   * }
   * ```
   */
  async refresh(
    refreshToken: string,
    newPayload?: Record<string, unknown>,
  ): Promise<TokenPair> {
    // 验证 Refresh Token
    let payload: JWTPayload;
    try {
      payload = await verifyToken(refreshToken, this.refreshTokenSecret, {
        issuer: this.issuer,
        audience: this.audience,
      });
    } catch {
      throw new Error($tr("auth.refresh.invalidRefreshToken"));
    }

    // 检查 Token 类型
    if (payload.type !== "refresh") {
      throw new Error($tr("auth.refresh.invalidTokenType"));
    }

    // 获取 Token ID
    const tokenId = payload.jti as string;
    if (!tokenId) {
      throw new Error($tr("auth.refresh.refreshTokenMissingId"));
    }

    // 从存储中获取 Token 数据
    const tokenData = await this.store.get(tokenId);
    if (!tokenData) {
      throw new Error($tr("auth.refresh.refreshTokenExpiredOrMissing"));
    }

    // 检查是否已撤销
    if (tokenData.revoked) {
      throw new Error($tr("auth.refresh.refreshTokenRevoked"));
    }

    // 删除旧的 Refresh Token
    await this.store.delete(tokenId);

    // 生成新的 Token 对
    const userId = tokenData.userId;
    const finalPayload = newPayload || { userId };

    return await this.generateTokenPair(finalPayload, {
      device: tokenData.device,
      ip: tokenData.ip,
    });
  }

  /**
   * 验证 Access Token
   *
   * @param accessToken - Access Token
   * @returns 验证后的载荷
   * @throws 如果 Token 无效或已过期
   */
  async verifyAccessToken(accessToken: string): Promise<JWTPayload> {
    const payload = await verifyToken(accessToken, this.accessTokenSecret, {
      issuer: this.issuer,
      audience: this.audience,
    });

    if (payload.type !== "access") {
      throw new Error($tr("auth.refresh.invalidTokenType"));
    }

    return payload;
  }

  /**
   * 撤销 Refresh Token
   *
   * @param refreshToken - Refresh Token
   *
   * @example
   * ```typescript
   * await tokenManager.revoke(refreshToken);
   * ```
   */
  async revoke(refreshToken: string): Promise<void> {
    try {
      const decoded = decodeToken(refreshToken);
      const tokenId = decoded.payload.jti as string;
      if (tokenId) {
        await this.store.delete(tokenId);
      }
    } catch {
      // 忽略解码错误
    }
  }

  /**
   * 撤销用户的所有 Refresh Token
   *
   * @param userId - 用户 ID
   *
   * @example
   * ```typescript
   * // 强制用户重新登录
   * await tokenManager.revokeAllByUser("123");
   * ```
   */
  async revokeAllByUser(userId: string): Promise<void> {
    await this.store.deleteByUser(userId);
  }

  /**
   * 检查 Access Token 是否需要刷新
   *
   * @param accessToken - Access Token
   * @param threshold - 剩余时间阈值（秒，默认 300 即 5 分钟）
   * @returns 是否需要刷新
   */
  shouldRefresh(accessToken: string, threshold: number = 300): boolean {
    try {
      const decoded = decodeToken(accessToken);
      const exp = decoded.payload.exp;
      if (!exp) return false;

      const remaining = exp - Math.floor(Date.now() / 1000);
      return remaining < threshold;
    } catch {
      return true;
    }
  }

  /**
   * 检查 Access Token 是否已过期
   *
   * @param accessToken - Access Token
   * @returns 是否已过期
   */
  isAccessTokenExpired(accessToken: string): boolean {
    return isTokenExpired(accessToken);
  }
}

// ============================================================================
// 工厂函数
// ============================================================================

/**
 * 创建 Token 管理器
 *
 * @param options - 配置选项
 * @returns TokenManager 实例
 */
export function createTokenManager(options: TokenManagerOptions): TokenManager {
  return new TokenManager(options);
}
