/**
 * @module @dreamer/auth/oauth
 *
 * OAuth2 认证模块
 *
 * 提供 OAuth2 客户端功能，支持：
 * - Authorization Code 授权码流程
 * - PKCE 扩展（推荐用于公开客户端）
 * - Token 交换
 * - 内置 Provider（GitHub、Google、微信、企业微信、钉钉）
 *
 * @example
 * ```typescript
 * import { OAuth2Client, GitHubProvider } from "@dreamer/auth/oauth";
 *
 * const github = new OAuth2Client({
 *   ...GitHubProvider,
 *   clientId: "your-client-id",
 *   clientSecret: "your-client-secret",
 *   redirectUri: "http://localhost:3000/callback",
 * });
 *
 * // 生成授权 URL
 * const authUrl = github.getAuthorizationUrl({ scope: "user:email" });
 *
 * // 交换 Token
 * const tokens = await github.exchangeCode(code);
 * ```
 */

import { $tr } from "./i18n.ts";

// ============================================================================
// 类型定义
// ============================================================================

/**
 * OAuth2 配置选项
 */
export interface OAuth2Config {
  /** 客户端 ID */
  clientId: string;
  /** 客户端密钥（公开客户端可不提供） */
  clientSecret?: string;
  /** 授权端点 */
  authorizationEndpoint: string;
  /** Token 端点 */
  tokenEndpoint: string;
  /** 用户信息端点（可选） */
  userInfoEndpoint?: string;
  /** 回调地址 */
  redirectUri: string;
  /** 默认权限范围 */
  scope?: string;
  /** 是否使用 PKCE（默认 false） */
  usePKCE?: boolean;
}

/**
 * 授权 URL 选项
 */
export interface AuthorizationUrlOptions {
  /** 权限范围（覆盖默认） */
  scope?: string;
  /** 状态参数（用于防止 CSRF） */
  state?: string;
  /** PKCE code_challenge（如果启用 PKCE） */
  codeChallenge?: string;
  /** PKCE code_challenge_method（默认 S256） */
  codeChallengeMethod?: "plain" | "S256";
  /** 额外参数 */
  extra?: Record<string, string>;
}

/**
 * Token 交换选项
 */
export interface ExchangeCodeOptions {
  /** PKCE code_verifier（如果启用 PKCE） */
  codeVerifier?: string;
}

/**
 * OAuth2 Token 响应
 */
export interface OAuth2TokenResponse {
  /** Access Token */
  access_token: string;
  /** Token 类型（通常是 "Bearer"） */
  token_type: string;
  /** 过期时间（秒） */
  expires_in?: number;
  /** Refresh Token（如果有） */
  refresh_token?: string;
  /** 权限范围 */
  scope?: string;
  /** ID Token（OpenID Connect） */
  id_token?: string;
}

/**
 * OAuth2 用户信息（标准化）
 */
export interface OAuth2UserInfo {
  /** 用户 ID（Provider 的唯一标识） */
  id: string;
  /** 用户名 */
  username?: string;
  /** 邮箱 */
  email?: string;
  /** 头像 URL */
  avatar?: string;
  /** 显示名称 */
  name?: string;
  /** Provider 名称 */
  provider: string;
  /** 原始数据 */
  raw: Record<string, unknown>;
}

/**
 * PKCE 参数
 */
export interface PKCEParams {
  /** code_verifier（需要保存用于交换 Token） */
  codeVerifier: string;
  /** code_challenge（发送给授权服务器） */
  codeChallenge: string;
  /** code_challenge_method */
  codeChallengeMethod: "S256";
}

// ============================================================================
// PKCE 辅助函数
// ============================================================================

/**
 * 生成随机字节并转换为 Base64URL
 */
function generateRandomString(length: number): string {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Base64URL 编码
 */
function base64UrlEncode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * 计算 SHA-256 哈希
 */
async function sha256(data: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const buffer = await globalThis.crypto.subtle.digest(
    "SHA-256",
    encoder.encode(data),
  );
  return new Uint8Array(buffer);
}

/**
 * 生成 PKCE 参数
 *
 * @returns PKCE 参数（code_verifier 和 code_challenge）
 *
 * @example
 * ```typescript
 * const pkce = await generatePKCE();
 * // 保存 pkce.codeVerifier 用于后续 Token 交换
 * const authUrl = client.getAuthorizationUrl({
 *   codeChallenge: pkce.codeChallenge,
 *   codeChallengeMethod: pkce.codeChallengeMethod,
 * });
 * ```
 */
export async function generatePKCE(): Promise<PKCEParams> {
  // 生成 43-128 字符的随机字符串作为 code_verifier
  const codeVerifier = generateRandomString(32);

  // 计算 code_challenge = BASE64URL(SHA256(code_verifier))
  const hash = await sha256(codeVerifier);
  const codeChallenge = base64UrlEncode(hash);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
  };
}

/**
 * 生成状态参数（用于防止 CSRF 攻击）
 *
 * @returns 随机状态字符串
 */
export function generateState(): string {
  return generateRandomString(16);
}

// ============================================================================
// OAuth2 客户端
// ============================================================================

/**
 * OAuth2 客户端
 *
 * 实现 OAuth2 Authorization Code 流程
 */
export class OAuth2Client {
  /** 配置 */
  private config: OAuth2Config;

  /**
   * 创建 OAuth2Client 实例
   *
   * @param config - OAuth2 配置
   */
  constructor(config: OAuth2Config) {
    this.config = config;
  }

  /**
   * 生成授权 URL
   *
   * @param options - 授权选项
   * @returns 授权 URL
   *
   * @example
   * ```typescript
   * const authUrl = client.getAuthorizationUrl({
   *   scope: "user:email",
   *   state: generateState(),
   * });
   * // 重定向用户到 authUrl
   * ```
   */
  getAuthorizationUrl(options: AuthorizationUrlOptions = {}): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: "code",
      scope: options.scope || this.config.scope || "",
    });

    if (options.state) {
      params.set("state", options.state);
    }

    // PKCE 支持
    if (options.codeChallenge) {
      params.set("code_challenge", options.codeChallenge);
      params.set(
        "code_challenge_method",
        options.codeChallengeMethod || "S256",
      );
    }

    // 额外参数
    if (options.extra) {
      for (const [key, value] of Object.entries(options.extra)) {
        params.set(key, value);
      }
    }

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * 交换授权码获取 Token
   *
   * @param code - 授权码
   * @param options - 交换选项
   * @returns Token 响应
   *
   * @example
   * ```typescript
   * const tokens = await client.exchangeCode(code, {
   *   codeVerifier: pkce.codeVerifier,
   * });
   * console.log(tokens.access_token);
   * ```
   */
  async exchangeCode(
    code: string,
    options: ExchangeCodeOptions = {},
  ): Promise<OAuth2TokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
    });

    // 添加 client_secret（如果有）
    if (this.config.clientSecret) {
      body.set("client_secret", this.config.clientSecret);
    }

    // PKCE 支持
    if (options.codeVerifier) {
      body.set("code_verifier", options.codeVerifier);
    }

    const response = await fetch(this.config.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error($tr("auth.oauth.tokenExchangeFailed", { error }));
    }

    return await response.json();
  }

  /**
   * 刷新 Token
   *
   * @param refreshToken - Refresh Token
   * @returns 新的 Token 响应
   */
  async refreshToken(refreshToken: string): Promise<OAuth2TokenResponse> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });

    if (this.config.clientSecret) {
      body.set("client_secret", this.config.clientSecret);
    }

    const response = await fetch(this.config.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error($tr("auth.oauth.tokenRefreshFailed", { error }));
    }

    return await response.json();
  }

  /**
   * 获取用户信息
   *
   * @param accessToken - Access Token
   * @returns 原始用户信息
   */
  async getUserInfoRaw(
    accessToken: string,
  ): Promise<Record<string, unknown>> {
    if (!this.config.userInfoEndpoint) {
      throw new Error($tr("auth.oauth.userInfoEndpointNotConfigured"));
    }

    const response = await fetch(this.config.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error($tr("auth.oauth.getUserInfoFailed", { error }));
    }

    return await response.json();
  }
}

// ============================================================================
// 内置 Provider 配置
// ============================================================================

/**
 * GitHub OAuth2 配置
 */
export const GitHubProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://github.com/login/oauth/authorize",
  tokenEndpoint: "https://github.com/login/oauth/access_token",
  userInfoEndpoint: "https://api.github.com/user",
  scope: "read:user user:email",
};

/**
 * Google OAuth2 配置
 */
export const GoogleProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
  userInfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
  scope: "openid email profile",
};

/**
 * 微信 OAuth2 配置（网页应用）
 */
export const WeChatProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://open.weixin.qq.com/connect/qrconnect",
  tokenEndpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
  userInfoEndpoint: "https://api.weixin.qq.com/sns/userinfo",
  scope: "snsapi_login",
};

/**
 * 企业微信 OAuth2 配置
 */
export const WeComProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://open.work.weixin.qq.com/wwopen/sso/qrConnect",
  tokenEndpoint: "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
  userInfoEndpoint: "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo",
  scope: "snsapi_base",
};

/**
 * 钉钉 OAuth2 配置
 */
export const DingTalkProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://login.dingtalk.com/oauth2/auth",
  tokenEndpoint: "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
  userInfoEndpoint: "https://api.dingtalk.com/v1.0/contact/users/me",
  scope: "openid",
};

/**
 * GitLab OAuth2 配置
 */
export const GitLabProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://gitlab.com/oauth/authorize",
  tokenEndpoint: "https://gitlab.com/oauth/token",
  userInfoEndpoint: "https://gitlab.com/api/v4/user",
  scope: "read_user",
};

/**
 * Gitee OAuth2 配置
 */
export const GiteeProvider: Partial<OAuth2Config> = {
  authorizationEndpoint: "https://gitee.com/oauth/authorize",
  tokenEndpoint: "https://gitee.com/oauth/token",
  userInfoEndpoint: "https://gitee.com/api/v5/user",
  scope: "user_info",
};

// ============================================================================
// 用户信息解析器
// ============================================================================

/**
 * 解析 GitHub 用户信息
 */
export function parseGitHubUser(data: Record<string, unknown>): OAuth2UserInfo {
  return {
    id: String(data.id),
    username: data.login as string,
    email: data.email as string,
    avatar: data.avatar_url as string,
    name: data.name as string,
    provider: "github",
    raw: data,
  };
}

/**
 * 解析 Google 用户信息
 */
export function parseGoogleUser(data: Record<string, unknown>): OAuth2UserInfo {
  return {
    id: data.id as string,
    username: data.email as string,
    email: data.email as string,
    avatar: data.picture as string,
    name: data.name as string,
    provider: "google",
    raw: data,
  };
}

/**
 * 解析微信用户信息
 */
export function parseWeChatUser(data: Record<string, unknown>): OAuth2UserInfo {
  return {
    id: data.unionid as string || data.openid as string,
    username: data.nickname as string,
    email: undefined,
    avatar: data.headimgurl as string,
    name: data.nickname as string,
    provider: "wechat",
    raw: data,
  };
}

/**
 * 解析 GitLab 用户信息
 */
export function parseGitLabUser(data: Record<string, unknown>): OAuth2UserInfo {
  return {
    id: String(data.id),
    username: data.username as string,
    email: data.email as string,
    avatar: data.avatar_url as string,
    name: data.name as string,
    provider: "gitlab",
    raw: data,
  };
}

/**
 * 解析 Gitee 用户信息
 */
export function parseGiteeUser(data: Record<string, unknown>): OAuth2UserInfo {
  return {
    id: String(data.id),
    username: data.login as string,
    email: data.email as string,
    avatar: data.avatar_url as string,
    name: data.name as string,
    provider: "gitee",
    raw: data,
  };
}

// ============================================================================
// 工厂函数
// ============================================================================

/**
 * 创建 OAuth2 客户端
 *
 * @param config - OAuth2 配置
 * @returns OAuth2Client 实例
 */
export function createOAuth2Client(config: OAuth2Config): OAuth2Client {
  return new OAuth2Client(config);
}

/**
 * 创建 GitHub OAuth2 客户端
 *
 * @param clientId - 客户端 ID
 * @param clientSecret - 客户端密钥
 * @param redirectUri - 回调地址
 * @returns OAuth2Client 实例
 */
export function createGitHubClient(
  clientId: string,
  clientSecret: string,
  redirectUri: string,
): OAuth2Client {
  return new OAuth2Client({
    ...GitHubProvider,
    clientId,
    clientSecret,
    redirectUri,
  } as OAuth2Config);
}

/**
 * 创建 Google OAuth2 客户端
 *
 * @param clientId - 客户端 ID
 * @param clientSecret - 客户端密钥
 * @param redirectUri - 回调地址
 * @returns OAuth2Client 实例
 */
export function createGoogleClient(
  clientId: string,
  clientSecret: string,
  redirectUri: string,
): OAuth2Client {
  return new OAuth2Client({
    ...GoogleProvider,
    clientId,
    clientSecret,
    redirectUri,
  } as OAuth2Config);
}
