/**
 * @fileoverview JWT 模块测试
 */

import { describe, expect, it } from "@dreamer/test";
import {
  decodeToken,
  generateECKeyPair,
  generateRSAKeyPair,
  getTokenExpiration,
  getTokenRemainingTime,
  isTokenExpired,
  signToken,
  verifyToken,
} from "../src/jwt.ts";

describe("signToken - JWT 签名", () => {
  it("应该使用 HS256 签名 JWT", async () => {
    const token = await signToken(
      { userId: "123", username: "admin" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );

    expect(token).toBeDefined();
    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);
  });

  it("应该包含正确的 payload", async () => {
    const token = await signToken(
      { userId: "123", role: "admin" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h", issuer: "test-app" },
    );

    const decoded = decodeToken(token);
    expect(decoded.payload.userId).toBe("123");
    expect(decoded.payload.role).toBe("admin");
    expect(decoded.payload.iss).toBe("test-app");
    expect(decoded.payload.exp).toBeDefined();
    expect(decoded.payload.iat).toBeDefined();
  });

  it("应该支持不同的过期时间格式", async () => {
    const token1h = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );
    const token1d = await signToken(
      { id: "2" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1d" },
    );
    const token30m = await signToken(
      { id: "3" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "30m" },
    );

    const decoded1h = decodeToken(token1h);
    const decoded1d = decodeToken(token1d);
    const decoded30m = decodeToken(token30m);

    // 1 小时后过期
    expect(decoded1h.payload.exp! - decoded1h.payload.iat!).toBe(3600);
    // 1 天后过期
    expect(decoded1d.payload.exp! - decoded1d.payload.iat!).toBe(86400);
    // 30 分钟后过期
    expect(decoded30m.payload.exp! - decoded30m.payload.iat!).toBe(1800);
  });
});

describe("verifyToken - JWT 验证", () => {
  it("应该验证有效的 JWT", async () => {
    const token = await signToken(
      { userId: "123" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );

    const payload = await verifyToken(
      token,
      "test-secret-key-for-jwt-testing-32ch",
    );
    expect(payload.userId).toBe("123");
  });

  it("应该拒绝错误的密钥", async () => {
    const token = await signToken(
      { userId: "123" },
      "correct-secret-key-for-jwt-test-32ch",
      { expiresIn: "1h" },
    );

    let error: Error | null = null;
    try {
      await verifyToken(token, "wrong-secret-key-for-jwt-test-32ch!");
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
  });

  it("应该拒绝过期的 Token", async () => {
    // 创建一个已过期的 Token
    const token = await signToken(
      { userId: "123" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1s" },
    );

    // 等待过期（增加等待时间确保过期）
    await new Promise((resolve) => setTimeout(resolve, 2000));

    let error: Error | null = null;
    try {
      await verifyToken(token, "test-secret-key-for-jwt-testing-32ch");
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
    expect(error!.message).toContain("过期");
  });

  it("应该验证签发者", async () => {
    const token = await signToken(
      { userId: "123" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h", issuer: "my-app" },
    );

    // 正确的签发者
    const payload = await verifyToken(
      token,
      "test-secret-key-for-jwt-testing-32ch",
      { issuer: "my-app" },
    );
    expect(payload.iss).toBe("my-app");

    // 错误的签发者
    let error: Error | null = null;
    try {
      await verifyToken(token, "test-secret-key-for-jwt-testing-32ch", {
        issuer: "other-app",
      });
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
    expect(error!.message).toContain("签发者不匹配");
  });
});

describe("decodeToken - JWT 解码", () => {
  it("应该解码 JWT Header 和 Payload", async () => {
    const token = await signToken(
      { userId: "123", name: "test" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );

    const decoded = decodeToken(token);

    expect(decoded.header.alg).toBe("HS256");
    expect(decoded.header.typ).toBe("JWT");
    expect(decoded.payload.userId).toBe("123");
    expect(decoded.payload.name).toBe("test");
    expect(decoded.signature).toBeDefined();
  });

  it("应该抛出无效 Token 格式错误", () => {
    expect(() => decodeToken("invalid")).toThrow("无效的 JWT Token 格式");
    expect(() => decodeToken("a.b")).toThrow("无效的 JWT Token 格式");
  });
});

describe("isTokenExpired - 过期检查", () => {
  it("应该返回 false 对于未过期的 Token", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );
    expect(isTokenExpired(token)).toBe(false);
  });

  it("应该返回 true 对于过期的 Token", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1s" },
    );
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(isTokenExpired(token)).toBe(true);
  });

  it("应该返回 true 对于无效的 Token", () => {
    expect(isTokenExpired("invalid-token")).toBe(true);
  });
});

describe("getTokenExpiration - 获取过期时间", () => {
  it("应该返回过期时间戳", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );
    const exp = getTokenExpiration(token);

    expect(exp).toBeDefined();
    expect(exp!).toBeGreaterThan(now);
    expect(exp! - now).toBeLessThanOrEqual(3601); // 允许 1 秒误差
    expect(exp! - now).toBeGreaterThanOrEqual(3599);
  });

  it("应该返回 null 对于无过期时间的 Token", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      {},
    );
    const exp = getTokenExpiration(token);
    expect(exp).toBeNull();
  });
});

describe("getTokenRemainingTime - 获取剩余时间", () => {
  it("应该返回正确的剩余时间", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1h" },
    );
    const remaining = getTokenRemainingTime(token);

    expect(remaining).toBeGreaterThan(3500);
    expect(remaining).toBeLessThanOrEqual(3600);
  });

  it("应该返回 0 对于过期的 Token", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      { expiresIn: "1s" },
    );
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const remaining = getTokenRemainingTime(token);
    expect(remaining).toBe(0);
  });

  it("应该返回 -1 对于无过期时间的 Token", async () => {
    const token = await signToken(
      { id: "1" },
      "test-secret-key-for-jwt-testing-32ch",
      {},
    );
    const remaining = getTokenRemainingTime(token);
    expect(remaining).toBe(-1);
  });
});

describe("generateRSAKeyPair - RSA 密钥对生成", () => {
  it("应该生成 RSA 密钥对", async () => {
    const { publicKey, privateKey } = await generateRSAKeyPair();

    expect(publicKey).toBeInstanceOf(CryptoKey);
    expect(privateKey).toBeInstanceOf(CryptoKey);
  });

  it("应该使用 RSA 密钥签名和验证", async () => {
    const { publicKey, privateKey } = await generateRSAKeyPair();

    const token = await signToken(
      { userId: "123" },
      privateKey,
      { algorithm: "RS256", expiresIn: "1h" },
    );

    // 使用 RS256 算法需要在 algorithm 中明确指定
    const payload = await verifyToken(token, publicKey, {
      algorithm: "RS256",
    });
    expect(payload.userId).toBe("123");
  });
});

describe("generateECKeyPair - ECDSA 密钥对生成", () => {
  it("应该生成 ECDSA 密钥对", async () => {
    const { publicKey, privateKey } = await generateECKeyPair();

    expect(publicKey).toBeInstanceOf(CryptoKey);
    expect(privateKey).toBeInstanceOf(CryptoKey);
  });

  it("应该使用 ECDSA 密钥签名和验证", async () => {
    const { publicKey, privateKey } = await generateECKeyPair("P-256");

    const token = await signToken(
      { userId: "456" },
      privateKey,
      { algorithm: "ES256", expiresIn: "1h" },
    );

    // 使用 ES256 算法需要在 algorithm 中明确指定
    const payload = await verifyToken(token, publicKey, {
      algorithm: "ES256",
    });
    expect(payload.userId).toBe("456");
  });
});
