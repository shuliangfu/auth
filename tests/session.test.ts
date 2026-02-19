/**
 * @fileoverview Session 认证模块测试
 */

import { beforeEach, describe, expect, it } from "@dreamer/test";
import {
  type AuthSessionData,
  AuthSessionManager,
  type CookieOptions,
  createAuthSession,
  type HttpContext,
  type SessionStore,
} from "../src/session.ts";
import type { AuthUser } from "../src/mod.ts";

// ============================================================================
// Mock 实现
// ============================================================================

/**
 * 内存 Session 存储（用于测试）
 */
class MemorySessionStore implements SessionStore {
  private sessions: Map<string, AuthSessionData> = new Map();

  get(sessionId: string): Promise<AuthSessionData | null> {
    return Promise.resolve(this.sessions.get(sessionId) || null);
  }

  set(
    sessionId: string,
    data: AuthSessionData,
    _maxAge: number,
  ): Promise<void> {
    this.sessions.set(sessionId, data);
    return Promise.resolve();
  }

  delete(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    return Promise.resolve();
  }

  has(sessionId: string): Promise<boolean> {
    return Promise.resolve(this.sessions.has(sessionId));
  }

  clear(): Promise<void> {
    this.sessions.clear();
    return Promise.resolve();
  }

  // 测试辅助方法
  getAll(): Map<string, AuthSessionData> {
    return this.sessions;
  }
}

/**
 * Mock HTTP 上下文
 */
function createMockContext(): HttpContext & { _cookies: Map<string, string> } {
  const cookies = new Map<string, string>();

  return {
    _cookies: cookies,
    cookies: {
      get(name: string): string | undefined {
        return cookies.get(name);
      },
      set(name: string, value: string, _options?: CookieOptions): void {
        cookies.set(name, value);
      },
      remove(name: string): void {
        cookies.delete(name);
      },
    },
    session: undefined,
  };
}

// ============================================================================
// 测试
// ============================================================================

describe("AuthSessionManager - Session 管理器", () => {
  let store: MemorySessionStore;
  let authSession: AuthSessionManager;

  beforeEach(() => {
    store = new MemorySessionStore();
    authSession = new AuthSessionManager({
      store,
      cookieName: "testSessionId",
      maxAge: 3600000,
    });
  });

  describe("login - 登录", () => {
    it("应该创建 Session 并设置 Cookie", async () => {
      const ctx = createMockContext();
      const user: AuthUser = {
        id: "123",
        username: "testuser",
        roles: ["user"],
      };

      await authSession.login(ctx, user);

      // 验证 Cookie 已设置
      expect(ctx._cookies.has("testSessionId")).toBe(true);

      // 验证 Session 数据
      expect(ctx.session).toBeDefined();
      expect(ctx.session!.user).toBeDefined();
      expect(ctx.session!.user!.id).toBe("123");
      expect(ctx.session!.user!.username).toBe("testuser");
      expect(ctx.session!.loginAt).toBeDefined();
    });

    it("应该将 Session 存储到 store", async () => {
      const ctx = createMockContext();
      const user: AuthUser = { id: "456", username: "admin" };

      await authSession.login(ctx, user);

      const sessionId = ctx._cookies.get("testSessionId")!;
      const storedSession = await store.get(sessionId);

      expect(storedSession).toBeDefined();
      expect(storedSession!.user!.id).toBe("456");
    });
  });

  describe("logout - 登出", () => {
    it("应该删除 Session 和 Cookie", async () => {
      const ctx = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      // 先登录
      await authSession.login(ctx, user);
      const sessionId = ctx._cookies.get("testSessionId")!;

      // 再登出
      await authSession.logout(ctx);

      // 验证 Cookie 已删除
      expect(ctx._cookies.has("testSessionId")).toBe(false);

      // 验证 Session 已删除
      expect(await store.get(sessionId)).toBeNull();

      // 验证上下文中的 Session 已清除
      expect(ctx.session).toBeUndefined();
    });

    it("应该处理未登录的情况", async () => {
      const ctx = createMockContext();

      // 直接登出，不应抛出错误
      await authSession.logout(ctx);

      expect(ctx.session).toBeUndefined();
    });
  });

  describe("isAuthenticated - 认证检查", () => {
    it("应该返回 true 对于已登录用户", async () => {
      const ctx = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      await authSession.login(ctx, user);

      expect(authSession.isAuthenticated(ctx)).toBe(true);
    });

    it("应该返回 false 对于未登录用户", () => {
      const ctx = createMockContext();

      expect(authSession.isAuthenticated(ctx)).toBe(false);
    });

    it("应该返回 false 对于登出后的用户", async () => {
      const ctx = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      await authSession.login(ctx, user);
      await authSession.logout(ctx);

      expect(authSession.isAuthenticated(ctx)).toBe(false);
    });
  });

  describe("getUser - 获取用户", () => {
    it("应该返回已登录用户信息", async () => {
      const ctx = createMockContext();
      const user: AuthUser = {
        id: "123",
        username: "testuser",
        email: "test@example.com",
        roles: ["admin"],
      };

      await authSession.login(ctx, user);

      const retrievedUser = authSession.getUser(ctx);

      expect(retrievedUser).toBeDefined();
      expect(retrievedUser!.id).toBe("123");
      expect(retrievedUser!.username).toBe("testuser");
      expect(retrievedUser!.email).toBe("test@example.com");
    });

    it("应该返回 null 对于未登录用户", () => {
      const ctx = createMockContext();

      expect(authSession.getUser(ctx)).toBeNull();
    });
  });

  describe("loadSession - 加载 Session", () => {
    it("应该从 Cookie 加载 Session", async () => {
      const ctx1 = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      // 在第一个上下文中登录
      await authSession.login(ctx1, user);
      const sessionId = ctx1._cookies.get("testSessionId")!;

      // 创建新的上下文，模拟新请求
      const ctx2 = createMockContext();
      ctx2._cookies.set("testSessionId", sessionId);

      // 加载 Session
      const loaded = await authSession.loadSession(ctx2);

      expect(loaded).toBe(true);
      expect(ctx2.session).toBeDefined();
      expect(ctx2.session!.user!.id).toBe("123");
    });

    it("应该返回 false 对于无 Cookie 的请求", async () => {
      const ctx = createMockContext();

      const loaded = await authSession.loadSession(ctx);

      expect(loaded).toBe(false);
    });

    it("应该返回 false 并清除 Cookie 对于无效 Session", async () => {
      const ctx = createMockContext();
      ctx._cookies.set("testSessionId", "invalid-session-id");

      const loaded = await authSession.loadSession(ctx);

      expect(loaded).toBe(false);
      expect(ctx._cookies.has("testSessionId")).toBe(false);
    });

    it("应该更新最后活动时间", async () => {
      const ctx1 = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      await authSession.login(ctx1, user);
      const sessionId = ctx1._cookies.get("testSessionId")!;
      const originalLastActive = ctx1.session!.lastActiveAt;

      // 等待一小段时间
      await new Promise((resolve) => setTimeout(resolve, 10));

      // 创建新上下文加载 Session
      const ctx2 = createMockContext();
      ctx2._cookies.set("testSessionId", sessionId);
      await authSession.loadSession(ctx2);

      expect(ctx2.session!.lastActiveAt).toBeGreaterThanOrEqual(
        originalLastActive!,
      );
    });
  });

  describe("middleware - 中间件", () => {
    it("应该自动加载 Session", async () => {
      const ctx1 = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      await authSession.login(ctx1, user);
      const sessionId = ctx1._cookies.get("testSessionId")!;

      // 使用中间件
      const ctx2 = createMockContext();
      ctx2._cookies.set("testSessionId", sessionId);

      let nextCalled = false;
      const middleware = authSession.middleware();
      await middleware(ctx2, () => {
        nextCalled = true;
        return Promise.resolve();
      });

      expect(nextCalled).toBe(true);
      expect(ctx2.session).toBeDefined();
      expect(ctx2.session!.user!.id).toBe("123");
    });

    it("应该在无 Session 时也调用 next", async () => {
      const ctx = createMockContext();

      let nextCalled = false;
      const middleware = authSession.middleware();
      await middleware(ctx, () => {
        nextCalled = true;
        return Promise.resolve();
      });

      expect(nextCalled).toBe(true);
    });
  });

  describe("requireAuth - 认证保护中间件", () => {
    it("应该允许已认证用户通过", async () => {
      const ctx = createMockContext();
      const user: AuthUser = { id: "123", username: "testuser" };

      await authSession.login(ctx, user);

      let nextCalled = false;
      const middleware = authSession.requireAuth();
      const result = await middleware(ctx, () => {
        nextCalled = true;
        return Promise.resolve();
      });

      expect(nextCalled).toBe(true);
      expect(result).toBeUndefined();
    });

    it("应该返回 401 对于未认证用户", async () => {
      const ctx = createMockContext();

      let nextCalled = false;
      const middleware = authSession.requireAuth();
      const result = await middleware(ctx, () => {
        nextCalled = true;
        return Promise.resolve();
      });

      expect(nextCalled).toBe(false);
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(401);
    });

    it("应该重定向未认证用户到指定 URL", async () => {
      const ctx = createMockContext();

      let nextCalled = false;
      // Response.redirect 需要完整 URL
      const middleware = authSession.requireAuth("http://localhost/login");
      const result = await middleware(ctx, () => {
        nextCalled = true;
        return Promise.resolve();
      });

      expect(nextCalled).toBe(false);
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(302);
    });
  });
});

describe("createAuthSession - 工厂函数", () => {
  it("应该创建 AuthSessionManager 实例", () => {
    const store = new MemorySessionStore();
    const authSession = createAuthSession({ store });

    expect(authSession).toBeInstanceOf(AuthSessionManager);
  });

  it("应该使用自定义配置", () => {
    const store = new MemorySessionStore();
    const authSession = createAuthSession({
      store,
      cookieName: "customSession",
      maxAge: 7200000,
    });

    expect(authSession).toBeInstanceOf(AuthSessionManager);
  });
});

describe("用户序列化", () => {
  it("应该支持自定义序列化函数", async () => {
    const store = new MemorySessionStore();
    const authSession = new AuthSessionManager({
      store,
      serializeUser: (user) => ({
        id: user.id,
        // 只保存 ID，不保存其他敏感信息
      }),
    });

    const ctx = createMockContext();
    const user: AuthUser = {
      id: "123",
      username: "testuser",
      password: "secret", // 敏感信息
    };

    await authSession.login(ctx, user);

    const sessionId = ctx._cookies.get("authSessionId")!;
    const storedSession = await store.get(sessionId);

    expect(storedSession!.user!.id).toBe("123");
    expect(storedSession!.user!.password).toBeUndefined();
  });

  it("应该支持自定义反序列化函数", async () => {
    const store = new MemorySessionStore();
    const userDb: Record<string, AuthUser> = {
      "123": { id: "123", username: "testuser", roles: ["admin"] },
    };

    const authSession = new AuthSessionManager({
      store,
      serializeUser: (user) => ({ id: user.id }),
      deserializeUser: (user) =>
        Promise.resolve(userDb[user.id as string] || null),
    });

    const ctx1 = createMockContext();
    await authSession.login(ctx1, { id: "123", username: "temp" });
    const sessionId = ctx1._cookies.get("authSessionId")!;

    // 新请求加载 Session
    const ctx2 = createMockContext();
    ctx2._cookies.set("authSessionId", sessionId);
    await authSession.loadSession(ctx2);

    // 应该获取到完整的用户信息
    expect(ctx2.session!.user!.username).toBe("testuser");
    expect(ctx2.session!.user!.roles).toEqual(["admin"]);
  });

  it("应该在用户不存在时删除 Session", async () => {
    const store = new MemorySessionStore();
    const authSession = new AuthSessionManager({
      store,
      deserializeUser: (_user) => Promise.resolve(null), // 用户不存在
    });

    const ctx1 = createMockContext();
    await authSession.login(ctx1, { id: "deleted-user" });
    const sessionId = ctx1._cookies.get("authSessionId")!;

    // 新请求加载 Session
    const ctx2 = createMockContext();
    ctx2._cookies.set("authSessionId", sessionId);
    const loaded = await authSession.loadSession(ctx2);

    expect(loaded).toBe(false);
    expect(ctx2._cookies.has("authSessionId")).toBe(false);
    expect(await store.get(sessionId)).toBeNull();
  });
});
