/**
 * @fileoverview Refresh Token 刷新机制示例
 *
 * 展示 Token 刷新、撤销、黑名单等功能
 */

import { MemoryTokenStore, TokenManager } from "../src/refresh.ts";
import { getTokenRemainingTime, isTokenExpired } from "../src/jwt.ts";

// ============================================================================
// 创建 Token 管理器
// ============================================================================

console.log("=== Refresh Token 示例 ===\n");

// 使用内存存储（生产环境建议使用 Redis）
const tokenStore = new MemoryTokenStore();

// 创建 Token 管理器
const tokenManager = new TokenManager({
  // 密钥必须至少 32 字符
  accessTokenSecret: "access-token-secret-key-for-jwt-32",
  refreshTokenSecret: "refresh-token-secret-key-for-jwt!",
  accessTokenExpiry: "15m", // Access Token 15 分钟过期
  refreshTokenExpiry: "7d", // Refresh Token 7 天过期
  issuer: "my-app",
  store: tokenStore,
});

// ============================================================================
// 生成 Token 对
// ============================================================================

console.log("=== 生成 Token 对 ===\n");

const tokens = await tokenManager.generateTokenPair({
  userId: "12345",
  username: "admin",
  role: "administrator",
});

console.log("Access Token:");
console.log(tokens.accessToken.slice(0, 50) + "...");
console.log("\nRefresh Token:");
console.log(tokens.refreshToken.slice(0, 50) + "...");
console.log(
  "\nAccess Token 过期时间:",
  new Date(tokens.accessTokenExpiresAt * 1000).toLocaleString(),
);
console.log(
  "Refresh Token 过期时间:",
  new Date(tokens.refreshTokenExpiresAt * 1000).toLocaleString(),
);

// ============================================================================
// 验证 Access Token
// ============================================================================

console.log("\n=== 验证 Access Token ===\n");

const payload = await tokenManager.verifyAccessToken(tokens.accessToken);
console.log("验证成功，Payload:");
console.log(JSON.stringify(payload, null, 2));

// ============================================================================
// 刷新 Token
// ============================================================================

console.log("\n=== 刷新 Token ===\n");

const newTokens = await tokenManager.refresh(tokens.refreshToken);

console.log("新的 Access Token:");
console.log(newTokens.accessToken.slice(0, 50) + "...");
console.log("\n新的 Refresh Token:");
console.log(newTokens.refreshToken.slice(0, 50) + "...");

// 旧的 Refresh Token 已失效
console.log("\n尝试使用旧的 Refresh Token:");
try {
  await tokenManager.refresh(tokens.refreshToken);
} catch (error) {
  console.log("错误:", (error as Error).message);
}

// ============================================================================
// Token 状态检查
// ============================================================================

console.log("\n=== Token 状态检查 ===\n");

// 使用 jwt.ts 的工具函数检查 Token 状态
const expired = isTokenExpired(newTokens.accessToken);
console.log("Access Token 是否已过期:", expired);

const remaining = getTokenRemainingTime(newTokens.accessToken);
console.log("剩余有效时间:", remaining, "秒");

// ============================================================================
// 撤销 Token
// ============================================================================

console.log("\n=== 撤销 Token ===\n");

// 撤销当前 Refresh Token
await tokenManager.revoke(newTokens.refreshToken);
console.log("已撤销当前 Refresh Token");

// 尝试使用已撤销的 Token
try {
  await tokenManager.refresh(newTokens.refreshToken);
} catch (error) {
  console.log("使用已撤销的 Token:", (error as Error).message);
}

// ============================================================================
// 撤销用户所有 Token
// ============================================================================

console.log("\n=== 撤销用户所有 Token ===\n");

// 生成多个 Token
const tokens1 = await tokenManager.generateTokenPair({ userId: "99999" });
const tokens2 = await tokenManager.generateTokenPair({ userId: "99999" });
const tokens3 = await tokenManager.generateTokenPair({ userId: "99999" });

console.log("用户 99999 生成了 3 个 Token");

// 撤销该用户的所有 Token
await tokenManager.revokeAllByUser("99999");
console.log("已撤销用户 99999 的所有 Token");

// 验证所有 Token 都已失效
for (
  const [name, t] of [["token1", tokens1], ["token2", tokens2], [
    "token3",
    tokens3,
  ]] as const
) {
  try {
    await tokenManager.refresh(t.refreshToken);
    console.log(`${name}: 仍然有效`);
  } catch {
    console.log(`${name}: 已失效`);
  }
}

// ============================================================================
// 实际应用流程
// ============================================================================

console.log("\n=== 实际应用流程 ===\n");

/**
 * 模拟 API 请求处理
 *
 * @param accessToken - 访问令牌
 */
async function handleApiRequest(accessToken: string): Promise<void> {
  console.log("1. 收到 API 请求");

  // 验证 Token
  try {
    const user = await tokenManager.verifyAccessToken(accessToken);
    console.log(`2. Token 有效，用户: ${user.userId}`);

    // 检查剩余时间
    const remainingTime = getTokenRemainingTime(accessToken);
    if (remainingTime !== null && remainingTime < 300) {
      console.log("3. Token 即将过期，建议客户端刷新");
    }

    console.log("4. 处理业务逻辑...");
    console.log("5. 返回响应");
  } catch (error) {
    console.log(`2. Token 无效: ${(error as Error).message}`);
    console.log("3. 返回 401 Unauthorized");
  }
}

// 生成新 Token 并测试
const testTokens = await tokenManager.generateTokenPair({
  userId: "test-user",
});
await handleApiRequest(testTokens.accessToken);
