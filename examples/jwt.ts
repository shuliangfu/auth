/**
 * @fileoverview JWT 签名和验证示例
 *
 * 展示 JWT Token 的生成、验证、解码等功能
 */

import {
  signToken,
  verifyToken,
  decodeToken,
  isTokenExpired,
  getTokenExpiration,
  getTokenRemainingTime,
  generateRSAKeyPair,
  generateECKeyPair,
} from "../src/jwt.ts";

// ============================================================================
// HMAC 算法（HS256）
// ============================================================================

console.log("=== HMAC 签名 (HS256) ===\n");

// 密钥必须至少 32 字符
const secret = "my-super-secret-key-for-jwt-signing-32ch";

// 生成 Token
const token = await signToken(
  {
    userId: "12345",
    username: "admin",
    role: "administrator",
  },
  secret,
  {
    expiresIn: "1h", // 1 小时后过期
    issuer: "my-app",
    audience: "my-api",
  }
);

console.log("生成的 Token:");
console.log(token);
console.log();

// 验证 Token
try {
  const payload = await verifyToken(token, secret, {
    issuer: "my-app",
    audience: "my-api",
  });
  console.log("验证成功，Payload:");
  console.log(JSON.stringify(payload, null, 2));
} catch (error) {
  console.error("验证失败:", error);
}

// ============================================================================
// 解码 Token（不验证签名）
// ============================================================================

console.log("\n=== 解码 Token ===\n");

const decoded = decodeToken(token);

console.log("Header:");
console.log(JSON.stringify(decoded.header, null, 2));

console.log("\nPayload:");
console.log(JSON.stringify(decoded.payload, null, 2));

console.log("\nSignature:");
console.log(decoded.signature);

// ============================================================================
// Token 过期检查
// ============================================================================

console.log("\n=== Token 过期检查 ===\n");

console.log("是否过期:", isTokenExpired(token));

const expiration = getTokenExpiration(token);
if (expiration) {
  console.log("过期时间:", new Date(expiration * 1000).toLocaleString());
}

const remaining = getTokenRemainingTime(token);
console.log("剩余时间:", remaining, "秒");

// ============================================================================
// RSA 算法（RS256）
// ============================================================================

console.log("\n=== RSA 签名 (RS256) ===\n");

// 生成 RSA 密钥对
const { publicKey, privateKey } = await generateRSAKeyPair();

console.log("生成 RSA 密钥对成功");

// 使用私钥签名
const rsaToken = await signToken(
  { userId: "67890", role: "user" },
  privateKey,
  {
    algorithm: "RS256",
    expiresIn: "24h",
  }
);

console.log("RSA Token:");
console.log(rsaToken.slice(0, 100) + "...");

// 使用公钥验证
const rsaPayload = await verifyToken(rsaToken, publicKey, {
  algorithm: "RS256",
});

console.log("\n验证成功，Payload:");
console.log(JSON.stringify(rsaPayload, null, 2));

// ============================================================================
// ECDSA 算法（ES256）
// ============================================================================

console.log("\n=== ECDSA 签名 (ES256) ===\n");

// 生成 ECDSA 密钥对
const ecKeys = await generateECKeyPair("P-256");

console.log("生成 ECDSA 密钥对成功");

// 使用私钥签名
const ecToken = await signToken(
  { userId: "11111", permissions: ["read", "write"] },
  ecKeys.privateKey,
  {
    algorithm: "ES256",
    expiresIn: "7d",
  }
);

console.log("ECDSA Token:");
console.log(ecToken.slice(0, 100) + "...");

// 使用公钥验证
const ecPayload = await verifyToken(ecToken, ecKeys.publicKey, {
  algorithm: "ES256",
});

console.log("\n验证成功，Payload:");
console.log(JSON.stringify(ecPayload, null, 2));

// ============================================================================
// 错误处理示例
// ============================================================================

console.log("\n=== 错误处理 ===\n");

// 验证错误的密钥
try {
  await verifyToken(token, "wrong-secret-key-for-jwt-testing!!!");
} catch (error) {
  console.log("密钥错误:", (error as Error).message);
}

// 验证过期 Token（模拟）
console.log("\n验证过期 Token 时会抛出错误");

// 验证算法不匹配
try {
  // 使用 HS256 签名的 Token，但要求 RS256
  await verifyToken(token, secret, {
    algorithm: "RS256",
  });
} catch (error) {
  console.log("算法不匹配:", (error as Error).message);
}
