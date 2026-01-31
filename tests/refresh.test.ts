/**
 * @fileoverview 刷新 Token 模块测试
 */

import { describe, it, expect, beforeEach } from "@dreamer/test";
import {
  TokenManager,
  MemoryTokenStore,
  createTokenManager,
} from "../src/refresh.ts";

describe("MemoryTokenStore - 内存存储", () => {
  let store: MemoryTokenStore;

  beforeEach(() => {
    store = new MemoryTokenStore();
  });

  it("应该保存和获取 Token", async () => {
    const tokenData = {
      tokenId: "test-id",
      userId: "user-123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
    };

    await store.save("test-id", tokenData);
    const retrieved = await store.get("test-id");

    expect(retrieved).toBeDefined();
    expect(retrieved!.tokenId).toBe("test-id");
    expect(retrieved!.userId).toBe("user-123");
  });

  it("应该返回 null 对于不存在的 Token", async () => {
    const result = await store.get("non-existent");
    expect(result).toBeNull();
  });

  it("应该删除 Token", async () => {
    const tokenData = {
      tokenId: "test-id",
      userId: "user-123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
    };

    await store.save("test-id", tokenData);
    await store.delete("test-id");
    const result = await store.get("test-id");

    expect(result).toBeNull();
  });

  it("应该按用户删除所有 Token", async () => {
    await store.save("token-1", {
      tokenId: "token-1",
      userId: "user-123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
    });

    await store.save("token-2", {
      tokenId: "token-2",
      userId: "user-123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
    });

    await store.save("token-3", {
      tokenId: "token-3",
      userId: "user-456",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
    });

    await store.deleteByUser("user-123");

    expect(await store.get("token-1")).toBeNull();
    expect(await store.get("token-2")).toBeNull();
    expect(await store.get("token-3")).toBeDefined();
  });

  it("应该返回 null 对于过期的 Token", async () => {
    const tokenData = {
      tokenId: "expired-token",
      userId: "user-123",
      expiresAt: Math.floor(Date.now() / 1000) - 100, // 已过期
      createdAt: Math.floor(Date.now() / 1000) - 200,
    };

    await store.save("expired-token", tokenData);
    const result = await store.get("expired-token");

    expect(result).toBeNull();
  });
});

describe("TokenManager - Token 管理器", () => {
  let tokenManager: TokenManager;

  beforeEach(() => {
    tokenManager = new TokenManager({
      // 密钥必须至少 32 字符
      accessTokenSecret: "access-secret-key-for-testing-32!",
      refreshTokenSecret: "refresh-secret-key-for-testing32!",
      accessTokenExpiry: "15m",
      refreshTokenExpiry: "7d",
      issuer: "test-app",
    });
  });

  it("应该生成 Token 对", async () => {
    const tokens = await tokenManager.generateTokenPair({
      userId: "123",
      username: "admin",
    });

    expect(tokens.accessToken).toBeDefined();
    expect(tokens.refreshToken).toBeDefined();
    expect(tokens.accessTokenExpiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(tokens.refreshTokenExpiresAt).toBeGreaterThan(Date.now() / 1000);
  });

  it("应该验证 Access Token", async () => {
    const tokens = await tokenManager.generateTokenPair({
      userId: "123",
      role: "admin",
    });

    const payload = await tokenManager.verifyAccessToken(tokens.accessToken);

    expect(payload.userId).toBe("123");
    expect(payload.role).toBe("admin");
    expect(payload.type).toBe("access");
  });

  it("应该刷新 Token", async () => {
    const tokens = await tokenManager.generateTokenPair({
      userId: "123",
    });

    const newTokens = await tokenManager.refresh(tokens.refreshToken, {
      userId: "123",
      refreshed: true,
    });

    expect(newTokens.accessToken).toBeDefined();
    expect(newTokens.refreshToken).toBeDefined();
    expect(newTokens.accessToken).not.toBe(tokens.accessToken);
    expect(newTokens.refreshToken).not.toBe(tokens.refreshToken);

    // 验证新的 Access Token
    const payload = await tokenManager.verifyAccessToken(newTokens.accessToken);
    expect(payload.refreshed).toBe(true);
  });

  it("应该拒绝使用已刷新的 Refresh Token", async () => {
    const tokens = await tokenManager.generateTokenPair({ userId: "123" });

    // 第一次刷新应该成功
    await tokenManager.refresh(tokens.refreshToken);

    // 第二次使用相同的 Refresh Token 应该失败
    let error: Error | null = null;
    try {
      await tokenManager.refresh(tokens.refreshToken);
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
  });

  it("应该撤销 Refresh Token", async () => {
    const tokens = await tokenManager.generateTokenPair({ userId: "123" });

    await tokenManager.revoke(tokens.refreshToken);

    let error: Error | null = null;
    try {
      await tokenManager.refresh(tokens.refreshToken);
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
  });

  it("应该撤销用户的所有 Token", async () => {
    const tokens1 = await tokenManager.generateTokenPair({ userId: "123" });
    const tokens2 = await tokenManager.generateTokenPair({ userId: "123" });
    const tokens3 = await tokenManager.generateTokenPair({ userId: "456" });

    await tokenManager.revokeAllByUser("123");

    let error1: Error | null = null;
    try {
      await tokenManager.refresh(tokens1.refreshToken);
    } catch (e) {
      error1 = e as Error;
    }
    expect(error1).not.toBeNull();

    let error2: Error | null = null;
    try {
      await tokenManager.refresh(tokens2.refreshToken);
    } catch (e) {
      error2 = e as Error;
    }
    expect(error2).not.toBeNull();

    // 其他用户的 Token 应该不受影响
    const newTokens = await tokenManager.refresh(tokens3.refreshToken);
    expect(newTokens.accessToken).toBeDefined();
  });

  it("应该检查 Token 是否需要刷新", async () => {
    const tokens = await tokenManager.generateTokenPair({ userId: "123" });

    // 刚生成的 Token 不需要刷新
    expect(tokenManager.shouldRefresh(tokens.accessToken, 300)).toBe(false);
  });

  it("应该检查 Token 是否过期", async () => {
    const tokens = await tokenManager.generateTokenPair({ userId: "123" });

    expect(tokenManager.isAccessTokenExpired(tokens.accessToken)).toBe(false);
  });
});

describe("createTokenManager - 工厂函数", () => {
  it("应该创建 TokenManager 实例", () => {
    const tokenManager = createTokenManager({
      accessTokenSecret: "secret1",
      refreshTokenSecret: "secret2",
    });

    expect(tokenManager).toBeInstanceOf(TokenManager);
  });
});
