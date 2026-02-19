/**
 * @module @dreamer/auth/session
 *
 * Session 认证集成模块
 *
 * 基于 @dreamer/session 库实现 Session 认证功能，包括：
 * - Session 中间件集成
 * - 用户登录/登出
 * - Session 数据管理
 *
 * @example
 * ```typescript
 * import { createAuthSession } from "@dreamer/auth/session";
 * import { RedisSessionAdapter } from "@dreamer/session";
 *
 * // 使用 @dreamer/session 的 Redis 适配器
 * const store = new RedisSessionAdapter({
 *   connection: { host: "localhost", port: 6379 },
 * });
 *
 * // 创建认证 Session 管理器
 * const authSession = createAuthSession({ store });
 *
 * // 登录
 * await authSession.login(ctx, { id: "123", username: "admin" });
 *
 * // 检查是否已认证
 * if (authSession.isAuthenticated(ctx)) {
 *   const user = authSession.getUser(ctx);
 * }
 *
 * // 登出
 * await authSession.logout(ctx);
 * ```
 */

import type { AuthUser } from "./mod.ts";
import type {
  SessionData as BaseSessionData,
  SessionStore,
} from "@dreamer/session";

// ============================================================================
// 类型定义
// ============================================================================

// 从 @dreamer/session 重新导出类型
export type { SessionStore };

/**
 * 认证 Session 数据（扩展自 @dreamer/session 的 SessionData）
 */
export interface AuthSessionData extends BaseSessionData {
  /** 用户信息 */
  user?: AuthUser;
  /** 登录时间 */
  loginAt?: number;
  /** 最后活动时间 */
  lastActiveAt?: number;
}

/**
 * Cookie 选项
 */
export interface CookieOptions {
  /** 过期时间（毫秒） */
  maxAge?: number;
  /** 过期日期 */
  expires?: Date;
  /** 域名 */
  domain?: string;
  /** 路径 */
  path?: string;
  /** 是否只在 HTTPS 下发送 */
  secure?: boolean;
  /** 是否禁止 JavaScript 访问 */
  httpOnly?: boolean;
  /** SameSite 策略 */
  sameSite?: "strict" | "lax" | "none";
}

/**
 * HTTP 上下文接口
 */
export interface HttpContext {
  /** Cookie 操作 */
  cookies: {
    get(name: string): string | undefined;
    set(name: string, value: string, options?: CookieOptions): void;
    remove(name: string): void;
  };
  /** Session 数据 */
  session?: AuthSessionData;
}

/**
 * Auth Session 配置选项
 */
export interface AuthSessionOptions {
  /** Session 存储适配器 */
  store: SessionStore;
  /** Cookie 名称（默认：authSessionId） */
  cookieName?: string;
  /** Session 过期时间（毫秒，默认：86400000，24 小时） */
  maxAge?: number;
  /** Cookie 选项 */
  cookie?: CookieOptions;
  /** Session ID 生成函数 */
  genId?: () => string;
  /** 用户序列化函数（存储前调用） */
  serializeUser?: (user: AuthUser) => AuthUser;
  /** 用户反序列化函数（读取后调用） */
  deserializeUser?: (user: AuthUser) => Promise<AuthUser | null>;
}

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 生成随机 Session ID
 *
 * @returns 64 字符的十六进制字符串
 */
function generateSessionId(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// Auth Session 管理器
// ============================================================================

/**
 * Auth Session 管理器
 *
 * 提供基于 Session 的用户认证管理
 */
export class AuthSessionManager {
  /** Session 存储 */
  private store: SessionStore;
  /** Cookie 名称 */
  private cookieName: string;
  /** Session 过期时间 */
  private maxAge: number;
  /** Cookie 选项 */
  private cookieOptions: CookieOptions;
  /** Session ID 生成函数 */
  private genId: () => string;
  /** 用户序列化函数 */
  private serializeUser: (user: AuthUser) => AuthUser;
  /** 用户反序列化函数 */
  private deserializeUser: (user: AuthUser) => Promise<AuthUser | null>;

  /**
   * 创建 AuthSessionManager 实例
   *
   * @param options - 配置选项
   */
  constructor(options: AuthSessionOptions) {
    this.store = options.store;
    this.cookieName = options.cookieName || "authSessionId";
    this.maxAge = options.maxAge || 86400000; // 24 小时
    this.cookieOptions = {
      httpOnly: true,
      path: "/",
      secure: false,
      sameSite: "lax",
      ...options.cookie,
    };
    this.genId = options.genId || generateSessionId;
    this.serializeUser = options.serializeUser || ((user) => user);
    this.deserializeUser = options.deserializeUser ||
      ((user) => Promise.resolve(user));
  }

  /**
   * 用户登录
   *
   * @param ctx - HTTP 上下文
   * @param user - 用户信息
   *
   * @example
   * ```typescript
   * await authSession.login(ctx, {
   *   id: "123",
   *   username: "admin",
   *   roles: ["admin"],
   * });
   * ```
   */
  async login(ctx: HttpContext, user: AuthUser): Promise<void> {
    // 生成新的 Session ID
    const sessionId = this.genId();

    // 序列化用户
    const serializedUser = this.serializeUser(user);

    // 创建 Session 数据
    const sessionData: AuthSessionData = {
      user: serializedUser,
      loginAt: Date.now(),
      lastActiveAt: Date.now(),
    };

    // 存储 Session
    await this.store.set(sessionId, sessionData, this.maxAge);

    // 设置 Cookie
    ctx.cookies.set(this.cookieName, sessionId, {
      ...this.cookieOptions,
      maxAge: this.maxAge,
    });

    // 更新上下文
    ctx.session = sessionData;
  }

  /**
   * 用户登出
   *
   * @param ctx - HTTP 上下文
   *
   * @example
   * ```typescript
   * await authSession.logout(ctx);
   * ```
   */
  async logout(ctx: HttpContext): Promise<void> {
    // 获取 Session ID
    const sessionId = ctx.cookies.get(this.cookieName);

    if (sessionId) {
      // 删除 Session
      await this.store.delete(sessionId);
    }

    // 删除 Cookie
    ctx.cookies.remove(this.cookieName);

    // 清除上下文中的 Session
    ctx.session = undefined;
  }

  /**
   * 检查用户是否已认证
   *
   * @param ctx - HTTP 上下文
   * @returns 是否已认证
   *
   * @example
   * ```typescript
   * if (authSession.isAuthenticated(ctx)) {
   *   // 用户已登录
   * }
   * ```
   */
  isAuthenticated(ctx: HttpContext): boolean {
    return ctx.session?.user !== undefined;
  }

  /**
   * 获取当前用户
   *
   * @param ctx - HTTP 上下文
   * @returns 用户信息，未登录返回 null
   *
   * @example
   * ```typescript
   * const user = authSession.getUser(ctx);
   * if (user) {
   *   console.log(user.username);
   * }
   * ```
   */
  getUser(ctx: HttpContext): AuthUser | null {
    return ctx.session?.user || null;
  }

  /**
   * 加载 Session（中间件使用）
   *
   * @param ctx - HTTP 上下文
   * @returns 是否成功加载
   */
  async loadSession(ctx: HttpContext): Promise<boolean> {
    const sessionId = ctx.cookies.get(this.cookieName);

    if (!sessionId) {
      return false;
    }

    const rawSessionData = await this.store.get(sessionId);

    if (!rawSessionData) {
      // Session 不存在，清除 Cookie
      ctx.cookies.remove(this.cookieName);
      return false;
    }

    // 转换为 AuthSessionData
    const sessionData = rawSessionData as AuthSessionData;

    // 反序列化用户
    if (sessionData.user) {
      const user = await this.deserializeUser(sessionData.user);
      if (!user) {
        // 用户不存在，删除 Session
        await this.store.delete(sessionId);
        ctx.cookies.remove(this.cookieName);
        return false;
      }
      sessionData.user = user;
    }

    // 更新最后活动时间
    sessionData.lastActiveAt = Date.now();
    await this.store.set(sessionId, sessionData, this.maxAge);

    // 设置上下文
    ctx.session = sessionData;

    return true;
  }

  /**
   * 创建 Session 中间件
   *
   * @returns 中间件函数
   *
   * @example
   * ```typescript
   * const app = new Http();
   * app.use(authSession.middleware());
   * ```
   */
  middleware(): (
    ctx: HttpContext,
    next: () => Promise<void>,
  ) => Promise<void> {
    return async (ctx: HttpContext, next: () => Promise<void>) => {
      await this.loadSession(ctx);
      await next();
    };
  }

  /**
   * 创建认证保护中间件
   *
   * @param redirectUrl - 未认证时重定向的 URL（可选）
   * @returns 中间件函数
   *
   * @example
   * ```typescript
   * // 返回 401 错误
   * app.use("/api/*", authSession.requireAuth());
   *
   * // 重定向到登录页
   * app.use("/admin/*", authSession.requireAuth("/login"));
   * ```
   */
  requireAuth(
    redirectUrl?: string,
  ): (ctx: HttpContext, next: () => Promise<void>) => Promise<Response | void> {
    return async (ctx: HttpContext, next: () => Promise<void>) => {
      if (!this.isAuthenticated(ctx)) {
        if (redirectUrl) {
          return Response.redirect(redirectUrl, 302);
        }
        return new Response("Unauthorized", { status: 401 });
      }
      await next();
    };
  }
}

// ============================================================================
// 工厂函数
// ============================================================================

/**
 * 创建 Auth Session 管理器
 *
 * @param options - 配置选项
 * @returns AuthSessionManager 实例
 *
 * @example
 * ```typescript
 * import { RedisSessionAdapter } from "@dreamer/session";
 *
 * const store = new RedisSessionAdapter({
 *   connection: { host: "localhost", port: 6379 },
 * });
 *
 * const authSession = createAuthSession({
 *   store,
 *   maxAge: 7 * 24 * 60 * 60 * 1000, // 7 天
 * });
 * ```
 */
export function createAuthSession(
  options: AuthSessionOptions,
): AuthSessionManager {
  return new AuthSessionManager(options);
}
