/**
 * @fileoverview OAuth2 认证示例
 *
 * 展示 OAuth2 Authorization Code 流程
 */

import {
  createGitHubClient,
  createGoogleClient,
  generatePKCE,
  generateState,
  OAuth2Client,
} from "../src/oauth.ts";

// ============================================================================
// GitHub OAuth2 配置
// ============================================================================

console.log("=== GitHub OAuth2 示例 ===\n");

// 使用工厂函数创建 GitHub 客户端
const githubClient = createGitHubClient(
  "your-github-client-id",
  "your-github-client-secret",
  "http://localhost:3000/callback",
);

// 生成授权 URL
const state = generateState();
const authUrl = githubClient.getAuthorizationUrl({
  state,
  // GitHub 特定参数
  extra: {
    allow_signup: "true",
  },
});

console.log("授权 URL:");
console.log(authUrl);
console.log("\nState（防 CSRF）:", state);

// ============================================================================
// Google OAuth2 + PKCE
// ============================================================================

console.log("\n=== Google OAuth2 + PKCE 示例 ===\n");

// 使用工厂函数创建 Google 客户端
const googleClient = createGoogleClient(
  "your-google-client-id",
  "your-google-client-secret",
  "http://localhost:3000/google/callback",
);

// 生成 PKCE 参数
const pkce = await generatePKCE();
console.log("PKCE 参数:");
console.log("Code Verifier:", pkce.codeVerifier);
console.log("Code Challenge:", pkce.codeChallenge);
console.log("Method:", pkce.codeChallengeMethod);

// 生成带 PKCE 的授权 URL
const googleAuthUrl = googleClient.getAuthorizationUrl({
  state: generateState(),
  codeChallenge: pkce.codeChallenge,
  codeChallengeMethod: pkce.codeChallengeMethod as "plain" | "S256",
  extra: {
    access_type: "offline", // 获取 refresh_token
    prompt: "consent",
  },
});

console.log("\nGoogle 授权 URL:");
console.log(googleAuthUrl);

// ============================================================================
// 处理回调（模拟）
// ============================================================================

console.log("\n=== 处理授权回调 ===\n");

// 模拟回调 URL
const callbackUrl = "http://localhost:3000/callback?code=auth_code_123&state=" +
  state;
console.log("回调 URL:", callbackUrl);

// 解析回调参数
const url = new URL(callbackUrl);
const code = url.searchParams.get("code");
const returnedState = url.searchParams.get("state");

console.log("授权码:", code);
console.log("返回的 State:", returnedState);

// 验证 State
if (returnedState !== state) {
  console.error("State 不匹配，可能是 CSRF 攻击！");
} else {
  console.log("State 验证通过 ✓");
}

// 交换 Token（实际使用时）
console.log("\n交换 Token（示例代码）:");
console.log(`
const tokens = await githubClient.exchangeCode(code, {
  // 如果使用 PKCE
  codeVerifier: pkce.codeVerifier,
});

console.log("Access Token:", tokens.accessToken);
console.log("Refresh Token:", tokens.refreshToken);
console.log("Expires In:", tokens.expiresIn);
`);

// ============================================================================
// 刷新 Token
// ============================================================================

console.log("\n=== 刷新 Token ===\n");

console.log("刷新 Token 示例代码:");
console.log(`
const newTokens = await googleClient.refreshToken(refreshToken);
console.log("新的 Access Token:", newTokens.accessToken);
`);

// ============================================================================
// 微信 OAuth2
// ============================================================================

console.log("\n=== 微信 OAuth2 示例 ===\n");

// 微信 OAuth2 需要手动配置端点
const wechatClient = new OAuth2Client({
  clientId: "your-wechat-appid",
  clientSecret: "your-wechat-secret",
  authorizationEndpoint: "https://open.weixin.qq.com/connect/qrconnect",
  tokenEndpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
  redirectUri: "http://localhost:3000/wechat/callback",
  scope: "snsapi_login",
});

const wechatAuthUrl = wechatClient.getAuthorizationUrl({
  state: generateState(),
  extra: {
    // 微信特定参数
    appid: "your-wechat-appid",
  },
});

console.log("微信授权 URL:");
console.log(wechatAuthUrl);

// ============================================================================
// PKCE 工具函数
// ============================================================================

console.log("\n=== PKCE 工具函数 ===\n");

// 使用 generatePKCE 生成完整的 PKCE 参数
const pkce2 = await generatePKCE();
console.log("Code Verifier:", pkce2.codeVerifier);
console.log("Code Challenge:", pkce2.codeChallenge);
console.log("Method:", pkce2.codeChallengeMethod);

// PKCE 用于授权请求
console.log("\n使用 PKCE 的授权流程:");
console.log(`
1. 生成 PKCE 参数
2. 将 code_challenge 发送到授权端点
3. 将 code_verifier 保存（用于后续 token 交换）
4. 用户授权后，用 code 和 code_verifier 交换 token
`);
