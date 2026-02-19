/**
 * @module @dreamer/auth/jwt
 *
 * JWT 签名和验证模块
 *
 * 基于 @dreamer/crypto 库实现完整的 JWT 功能，包括：
 * - JWT 签名生成（支持 HS256/HS384/HS512/RS256/RS384/RS512/ES256/ES384/ES512）
 * - JWT 签名验证
 * - JWT 解码（不验证签名）
 *
 * @example
 * ```typescript
 * import { signToken, verifyToken, decodeToken } from "@dreamer/auth/jwt";
 *
 * // 生成 JWT
 * const token = await signToken({ userId: "123" }, "secret", { expiresIn: "1h" });
 *
 * // 验证 JWT
 * const payload = await verifyToken(token, "secret");
 *
 * // 解码 JWT（不验证签名）
 * const decoded = decodeToken(token);
 * ```
 */

import {
  decodeJWT,
  generateECDSAKeyPair,
  generateRSASigningKeyPair,
  type JWTOptions,
  type JWTPayload,
  signJWT,
  verifyJWT,
} from "@dreamer/crypto";
import { $tr } from "./i18n.ts";

// ============================================================================
// 类型定义
// ============================================================================

/**
 * JWT 算法类型
 */
export type JwtAlgorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512";

/**
 * JWT 签名选项
 */
export interface SignTokenOptions {
  /** 算法（默认 HS256） */
  algorithm?: JwtAlgorithm;
  /** 过期时间（如 "1h", "24h", "7d"） */
  expiresIn?: string;
  /** 签发者 */
  issuer?: string;
  /** 受众 */
  audience?: string;
  /** 主题 */
  subject?: string;
  /** 签发时间 */
  issuedAt?: Date;
  /** 生效时间 */
  notBefore?: Date;
}

/** 支持的 JWT 算法类型 */
export type JWTAlgorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512";

/**
 * JWT 验证选项
 */
export interface VerifyTokenOptions {
  /** 签发者（验证时检查） */
  issuer?: string;
  /** 受众（验证时检查） */
  audience?: string;
  /** 是否忽略过期检查（默认 false） */
  ignoreExpiration?: boolean;
  /**
   * 允许的算法白名单（安全关键）
   *
   * 防止算法混淆攻击。可传单个算法或算法数组。
   * 如果不指定，默认只允许 HS256。
   *
   * @example
   * // 允许单个算法
   * { algorithm: "RS256" }
   * // 允许多个算法
   * { algorithm: ["RS256", "RS512"] }
   */
  algorithm?: JWTAlgorithm | JWTAlgorithm[];
}

/**
 * JWT 解码结果
 */
export interface DecodedToken {
  /** JWT Header */
  header: {
    alg: string;
    typ: string;
    [key: string]: unknown;
  };
  /** JWT Payload */
  payload: JWTPayload;
  /** 签名（Base64URL 编码） */
  signature: string;
}

/**
 * 密钥对类型
 */
export interface KeyPair {
  /** 公钥 */
  publicKey: CryptoKey;
  /** 私钥 */
  privateKey: CryptoKey;
}

// ============================================================================
// JWT 签名生成
// ============================================================================

/**
 * 生成 JWT Token
 *
 * @param payload - JWT 载荷
 * @param secret - 密钥（字符串用于 HMAC，CryptoKey 用于 RSA/ECDSA）
 * @param options - 签名选项
 * @returns JWT Token 字符串
 *
 * @example
 * ```typescript
 * // 使用 HMAC 算法（默认 HS256）
 * const token = await signToken({ userId: "123" }, "my-secret", {
 *   expiresIn: "1h",
 *   issuer: "my-app",
 * });
 *
 * // 使用 RSA 算法
 * const { privateKey } = await generateRSAKeyPair();
 * const token = await signToken({ userId: "123" }, privateKey, {
 *   algorithm: "RS256",
 *   expiresIn: "24h",
 * });
 * ```
 */
/** 密钥最小长度（字节） */
const MIN_SECRET_LENGTH = 32;

/**
 * 验证密钥强度
 *
 * @param secret - 密钥
 * @param algorithm - 使用的算法
 * @throws 密钥强度不足时抛出错误
 */
function validateSecretStrength(
  secret: string | CryptoKey,
  algorithm: string,
): void {
  // 只对 HMAC 算法验证字符串密钥长度
  if (typeof secret === "string" && algorithm.startsWith("HS")) {
    if (secret.length < MIN_SECRET_LENGTH) {
      throw new Error(
        $tr("auth.jwt.secretTooShort", {
          min: String(MIN_SECRET_LENGTH),
          current: String(secret.length),
        }),
      );
    }
  }
}

export async function signToken(
  payload: Record<string, unknown>,
  secret: string | CryptoKey,
  options: SignTokenOptions = {},
): Promise<string> {
  const algorithm = options.algorithm || "HS256";

  // 安全关键：验证密钥强度
  validateSecretStrength(secret, algorithm);

  const jwtOptions: JWTOptions = {
    algorithm,
    expiresIn: options.expiresIn,
    issuer: options.issuer,
    audience: options.audience,
    subject: options.subject,
    issuedAt: options.issuedAt,
    notBefore: options.notBefore,
  };

  return await signJWT(payload as JWTPayload, secret, jwtOptions);
}

// ============================================================================
// JWT 签名验证
// ============================================================================

/**
 * 验证 JWT Token
 *
 * @param token - JWT Token
 * @param secret - 密钥（字符串用于 HMAC，CryptoKey 用于 RSA/ECDSA）
 * @param options - 验证选项
 * @returns 验证后的 payload
 * @throws 验证失败时抛出错误
 *
 * @example
 * ```typescript
 * try {
 *   const payload = await verifyToken(token, "my-secret", {
 *     issuer: "my-app",
 *   });
 *   console.log(payload.userId);
 * } catch (error) {
 *   console.error("Token 验证失败:", error.message);
 * }
 * ```
 */
export async function verifyToken(
  token: string,
  secret: string | CryptoKey,
  options: VerifyTokenOptions = {},
): Promise<JWTPayload> {
  // 安全关键：先检查算法白名单，防止算法混淆攻击
  // 支持单个算法或算法数组
  const algorithmOption = options.algorithm;
  const allowedAlgorithms: JWTAlgorithm[] = algorithmOption
    ? Array.isArray(algorithmOption) ? algorithmOption : [algorithmOption]
    : ["HS256"]; // 默认只允许 HS256

  const decoded = decodeJWT(token);
  const tokenAlgorithm = decoded.header.alg as JWTAlgorithm;

  if (!allowedAlgorithms.includes(tokenAlgorithm)) {
    throw new Error(
      $tr("auth.jwt.algorithmNotAllowed", {
        alg: tokenAlgorithm,
        allowed: allowedAlgorithms.join(", "),
      }),
    );
  }

  // 验证签名
  const payload = await verifyJWT(token, secret);

  // 额外验证：签发者
  if (options.issuer && payload.iss !== options.issuer) {
    throw new Error($tr("auth.jwt.issuerMismatch"));
  }

  // 额外验证：受众
  if (options.audience && payload.aud !== options.audience) {
    throw new Error($tr("auth.jwt.audienceMismatch"));
  }

  return payload;
}

// ============================================================================
// JWT 解码
// ============================================================================

/**
 * 解码 JWT Token（不验证签名）
 *
 * 注意：此函数仅解码 Token，不验证签名。
 * 生产环境中应使用 verifyToken 进行签名验证。
 *
 * @param token - JWT Token
 * @returns 解码后的 Token 结构
 * @throws Token 格式无效时抛出错误
 *
 * @example
 * ```typescript
 * const decoded = decodeToken(token);
 * console.log(decoded.header.alg); // "HS256"
 * console.log(decoded.payload.userId); // "123"
 * ```
 */
export function decodeToken(token: string): DecodedToken {
  const result = decodeJWT(token);
  return {
    header: result.header as DecodedToken["header"],
    payload: result.payload,
    signature: result.signature,
  };
}

// ============================================================================
// 密钥对生成
// ============================================================================

/**
 * 生成 RSA 签名密钥对
 *
 * @param modulusLength - 模长（默认 2048）
 * @returns RSA 密钥对
 *
 * @example
 * ```typescript
 * const { publicKey, privateKey } = await generateRSAKeyPair();
 *
 * // 使用私钥签名
 * const token = await signToken({ userId: "123" }, privateKey, {
 *   algorithm: "RS256",
 * });
 *
 * // 使用公钥验证
 * const payload = await verifyToken(token, publicKey);
 * ```
 */
export async function generateRSAKeyPair(
  modulusLength: number = 2048,
): Promise<KeyPair> {
  return await generateRSASigningKeyPair(modulusLength);
}

/**
 * 生成 ECDSA 签名密钥对
 *
 * @param namedCurve - 曲线名称（默认 P-256）
 * @returns ECDSA 密钥对
 *
 * @example
 * ```typescript
 * const { publicKey, privateKey } = await generateECKeyPair("P-256");
 *
 * // 使用私钥签名
 * const token = await signToken({ userId: "123" }, privateKey, {
 *   algorithm: "ES256",
 * });
 *
 * // 使用公钥验证
 * const payload = await verifyToken(token, publicKey);
 * ```
 */
export async function generateECKeyPair(
  namedCurve: "P-256" | "P-384" | "P-521" = "P-256",
): Promise<KeyPair> {
  return await generateECDSAKeyPair(namedCurve);
}

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 检查 Token 是否过期
 *
 * @param token - JWT Token
 * @returns 是否过期
 *
 * @example
 * ```typescript
 * if (isTokenExpired(token)) {
 *   console.log("Token 已过期");
 * }
 * ```
 */
export function isTokenExpired(token: string): boolean {
  try {
    const decoded = decodeToken(token);
    const exp = decoded.payload.exp;
    if (!exp) return false;
    return Date.now() / 1000 > exp;
  } catch {
    return true;
  }
}

/**
 * 获取 Token 过期时间
 *
 * @param token - JWT Token
 * @returns 过期时间戳（秒），如果没有过期时间则返回 null
 *
 * @example
 * ```typescript
 * const expTime = getTokenExpiration(token);
 * if (expTime) {
 *   console.log("过期时间:", new Date(expTime * 1000));
 * }
 * ```
 */
export function getTokenExpiration(token: string): number | null {
  try {
    const decoded = decodeToken(token);
    return decoded.payload.exp || null;
  } catch {
    return null;
  }
}

/**
 * 获取 Token 剩余有效时间
 *
 * @param token - JWT Token
 * @returns 剩余时间（秒），如果已过期返回 0，如果没有过期时间返回 -1
 *
 * @example
 * ```typescript
 * const remaining = getTokenRemainingTime(token);
 * if (remaining > 0) {
 *   console.log(`Token 将在 ${remaining} 秒后过期`);
 * } else if (remaining === 0) {
 *   console.log("Token 已过期");
 * } else {
 *   console.log("Token 没有过期时间");
 * }
 * ```
 */
export function getTokenRemainingTime(token: string): number {
  try {
    const decoded = decodeToken(token);
    const exp = decoded.payload.exp;
    if (!exp) return -1;
    const remaining = exp - Math.floor(Date.now() / 1000);
    return remaining > 0 ? remaining : 0;
  } catch {
    return 0;
  }
}

// 重新导出 crypto 库的 JWT 类型
export type { JWTOptions, JWTPayload };
