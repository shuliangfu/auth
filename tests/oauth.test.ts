/**
 * @fileoverview OAuth2 模块测试
 */

import { describe, expect, it } from "@dreamer/test";
import {
  createGitHubClient,
  createGoogleClient,
  createOAuth2Client,
  generatePKCE,
  generateState,
  GiteeProvider,
  GitHubProvider,
  GitLabProvider,
  GoogleProvider,
  OAuth2Client,
  parseGiteeUser,
  parseGitHubUser,
  parseGitLabUser,
  parseGoogleUser,
  WeChatProvider,
} from "../src/oauth.ts";

describe("generatePKCE - PKCE 参数生成", () => {
  it("应该生成 code_verifier 和 code_challenge", async () => {
    const pkce = await generatePKCE();

    expect(pkce.codeVerifier).toBeDefined();
    expect(pkce.codeChallenge).toBeDefined();
    expect(pkce.codeChallengeMethod).toBe("S256");

    // code_verifier 应该是 43-128 字符
    expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(32);

    // code_challenge 应该是 Base64URL 编码
    expect(pkce.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("应该每次生成不同的 PKCE 参数", async () => {
    const pkce1 = await generatePKCE();
    const pkce2 = await generatePKCE();

    expect(pkce1.codeVerifier).not.toBe(pkce2.codeVerifier);
    expect(pkce1.codeChallenge).not.toBe(pkce2.codeChallenge);
  });
});

describe("generateState - 状态参数生成", () => {
  it("应该生成随机状态字符串", () => {
    const state = generateState();

    expect(state).toBeDefined();
    expect(state.length).toBeGreaterThan(0);
  });

  it("应该每次生成不同的状态", () => {
    const state1 = generateState();
    const state2 = generateState();

    expect(state1).not.toBe(state2);
  });
});

describe("OAuth2Client - 客户端", () => {
  const testConfig = {
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    authorizationEndpoint: "https://example.com/oauth/authorize",
    tokenEndpoint: "https://example.com/oauth/token",
    userInfoEndpoint: "https://example.com/api/user",
    redirectUri: "http://localhost:3000/callback",
    scope: "read write",
  };

  it("应该生成授权 URL", () => {
    const client = new OAuth2Client(testConfig);
    const authUrl = client.getAuthorizationUrl();

    expect(authUrl).toContain(testConfig.authorizationEndpoint);
    expect(authUrl).toContain(`client_id=${testConfig.clientId}`);
    expect(authUrl).toContain(
      `redirect_uri=${encodeURIComponent(testConfig.redirectUri)}`,
    );
    expect(authUrl).toContain("response_type=code");
    // URLSearchParams 使用 + 代替空格
    expect(authUrl).toContain("scope=read+write");
  });

  it("应该支持自定义 scope", () => {
    const client = new OAuth2Client(testConfig);
    const authUrl = client.getAuthorizationUrl({ scope: "custom_scope" });

    expect(authUrl).toContain("scope=custom_scope");
  });

  it("应该支持 state 参数", () => {
    const client = new OAuth2Client(testConfig);
    const state = "random-state-123";
    const authUrl = client.getAuthorizationUrl({ state });

    expect(authUrl).toContain(`state=${state}`);
  });

  it("应该支持 PKCE", async () => {
    const client = new OAuth2Client(testConfig);
    const pkce = await generatePKCE();
    const authUrl = client.getAuthorizationUrl({
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
    });

    expect(authUrl).toContain(`code_challenge=${pkce.codeChallenge}`);
    expect(authUrl).toContain("code_challenge_method=S256");
  });

  it("应该支持额外参数", () => {
    const client = new OAuth2Client(testConfig);
    const authUrl = client.getAuthorizationUrl({
      extra: {
        prompt: "consent",
        access_type: "offline",
      },
    });

    expect(authUrl).toContain("prompt=consent");
    expect(authUrl).toContain("access_type=offline");
  });
});

describe("内置 Provider 配置", () => {
  it("GitHub Provider 应该有正确的端点", () => {
    expect(GitHubProvider.authorizationEndpoint).toBe(
      "https://github.com/login/oauth/authorize",
    );
    expect(GitHubProvider.tokenEndpoint).toBe(
      "https://github.com/login/oauth/access_token",
    );
    expect(GitHubProvider.userInfoEndpoint).toBe("https://api.github.com/user");
  });

  it("Google Provider 应该有正确的端点", () => {
    expect(GoogleProvider.authorizationEndpoint).toBe(
      "https://accounts.google.com/o/oauth2/v2/auth",
    );
    expect(GoogleProvider.tokenEndpoint).toBe(
      "https://oauth2.googleapis.com/token",
    );
  });

  it("WeChat Provider 应该有正确的端点", () => {
    expect(WeChatProvider.authorizationEndpoint).toBe(
      "https://open.weixin.qq.com/connect/qrconnect",
    );
  });

  it("GitLab Provider 应该有正确的端点", () => {
    expect(GitLabProvider.authorizationEndpoint).toBe(
      "https://gitlab.com/oauth/authorize",
    );
    expect(GitLabProvider.tokenEndpoint).toBe("https://gitlab.com/oauth/token");
  });

  it("Gitee Provider 应该有正确的端点", () => {
    expect(GiteeProvider.authorizationEndpoint).toBe(
      "https://gitee.com/oauth/authorize",
    );
    expect(GiteeProvider.tokenEndpoint).toBe("https://gitee.com/oauth/token");
  });
});

describe("用户信息解析器", () => {
  it("parseGitHubUser 应该正确解析", () => {
    const rawData = {
      id: 12345,
      login: "testuser",
      email: "test@example.com",
      avatar_url: "https://avatar.url",
      name: "Test User",
    };

    const user = parseGitHubUser(rawData);

    expect(user.id).toBe("12345");
    expect(user.username).toBe("testuser");
    expect(user.email).toBe("test@example.com");
    expect(user.avatar).toBe("https://avatar.url");
    expect(user.name).toBe("Test User");
    expect(user.provider).toBe("github");
    expect(user.raw).toBe(rawData);
  });

  it("parseGoogleUser 应该正确解析", () => {
    const rawData = {
      id: "google-id-123",
      email: "test@gmail.com",
      picture: "https://picture.url",
      name: "Test User",
    };

    const user = parseGoogleUser(rawData);

    expect(user.id).toBe("google-id-123");
    expect(user.email).toBe("test@gmail.com");
    expect(user.avatar).toBe("https://picture.url");
    expect(user.name).toBe("Test User");
    expect(user.provider).toBe("google");
  });

  it("parseGitLabUser 应该正确解析", () => {
    const rawData = {
      id: 67890,
      username: "gitlabuser",
      email: "test@gitlab.com",
      avatar_url: "https://gitlab-avatar.url",
      name: "GitLab User",
    };

    const user = parseGitLabUser(rawData);

    expect(user.id).toBe("67890");
    expect(user.username).toBe("gitlabuser");
    expect(user.email).toBe("test@gitlab.com");
    expect(user.avatar).toBe("https://gitlab-avatar.url");
    expect(user.name).toBe("GitLab User");
    expect(user.provider).toBe("gitlab");
  });

  it("parseGiteeUser 应该正确解析", () => {
    const rawData = {
      id: 11111,
      login: "giteeuser",
      email: "test@gitee.com",
      avatar_url: "https://gitee-avatar.url",
      name: "Gitee User",
    };

    const user = parseGiteeUser(rawData);

    expect(user.id).toBe("11111");
    expect(user.username).toBe("giteeuser");
    expect(user.email).toBe("test@gitee.com");
    expect(user.avatar).toBe("https://gitee-avatar.url");
    expect(user.name).toBe("Gitee User");
    expect(user.provider).toBe("gitee");
  });
});

describe("工厂函数", () => {
  it("createOAuth2Client 应该创建客户端", () => {
    const client = createOAuth2Client({
      clientId: "test",
      authorizationEndpoint: "https://example.com/auth",
      tokenEndpoint: "https://example.com/token",
      redirectUri: "http://localhost/callback",
    });

    expect(client).toBeInstanceOf(OAuth2Client);
  });

  it("createGitHubClient 应该创建 GitHub 客户端", () => {
    const client = createGitHubClient(
      "client-id",
      "client-secret",
      "http://localhost/callback",
    );

    expect(client).toBeInstanceOf(OAuth2Client);

    const authUrl = client.getAuthorizationUrl();
    expect(authUrl).toContain("github.com");
  });

  it("createGoogleClient 应该创建 Google 客户端", () => {
    const client = createGoogleClient(
      "client-id",
      "client-secret",
      "http://localhost/callback",
    );

    expect(client).toBeInstanceOf(OAuth2Client);

    const authUrl = client.getAuthorizationUrl();
    expect(authUrl).toContain("accounts.google.com");
  });
});
