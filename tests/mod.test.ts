/**
 * @fileoverview Auth 模块基础功能测试
 */

import { describe, expect, it } from "@dreamer/test";
import {
  type AuthUser,
  createBasicAuthHeader,
  createBearerAuthHeader,
  extractUserFromJwt,
  getRequiredRoles,
  hasAllPermissions,
  hasAllRoles,
  hasAnyPermission,
  hasAnyRole,
  hasPermission,
  hasRole,
  isJwtExpired,
  type JwtPayload,
  matchPath,
  parseBasicAuth,
  parseBearerToken,
  parseJwt,
  requiresAuth,
  validateJwtClaims,
} from "../src/mod.ts";

describe("parseBearerToken - Bearer Token 解析", () => {
  it("应该解析有效的 Bearer Token", () => {
    const token = parseBearerToken(
      "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature",
    );
    expect(token).toBe("eyJhbGciOiJIUzI1NiJ9.test.signature");
  });

  it("应该返回 null 对于 null 输入", () => {
    expect(parseBearerToken(null)).toBeNull();
  });

  it("应该返回 null 对于非 Bearer 前缀", () => {
    expect(parseBearerToken("Basic dXNlcjpwYXNz")).toBeNull();
    expect(parseBearerToken("Token abc123")).toBeNull();
  });

  it("应该返回 null 对于空字符串", () => {
    expect(parseBearerToken("")).toBeNull();
  });
});

describe("parseBasicAuth - Basic Auth 解析", () => {
  it("应该解析有效的 Basic Auth", () => {
    // "user:pass" base64 编码
    const credentials = parseBasicAuth("Basic dXNlcjpwYXNz");
    expect(credentials).toEqual({ username: "user", password: "pass" });
  });

  it("应该处理包含冒号的密码", () => {
    // "user:pass:word" base64 编码
    const credentials = parseBasicAuth("Basic dXNlcjpwYXNzOndvcmQ=");
    expect(credentials).toEqual({ username: "user", password: "pass:word" });
  });

  it("应该返回 null 对于无效输入", () => {
    expect(parseBasicAuth(null)).toBeNull();
    expect(parseBasicAuth("Bearer token")).toBeNull();
    expect(parseBasicAuth("Basic !!!")).toBeNull();
  });
});

describe("createBasicAuthHeader - Basic Auth 头生成", () => {
  it("应该生成正确的 Basic Auth 头", () => {
    const header = createBasicAuthHeader("user", "pass");
    expect(header).toBe("Basic dXNlcjpwYXNz");
  });
});

describe("createBearerAuthHeader - Bearer Auth 头生成", () => {
  it("应该生成正确的 Bearer Auth 头", () => {
    const header = createBearerAuthHeader("my-token");
    expect(header).toBe("Bearer my-token");
  });
});

describe("parseJwt - JWT 解析", () => {
  it("应该解析有效的 JWT", () => {
    // 手动构造一个简单的 JWT
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = btoa(JSON.stringify({ sub: "123", name: "Test" }));
    const signature = "test-signature";
    const token = `${header}.${payload}.${signature}`;

    const parsed = parseJwt(token);
    expect(parsed).toBeDefined();
    expect(parsed!.sub).toBe("123");
    expect(parsed!.name).toBe("Test");
  });

  it("应该返回 null 对于无效 Token", () => {
    expect(parseJwt("invalid")).toBeNull();
    expect(parseJwt("a.b")).toBeNull();
    expect(parseJwt("")).toBeNull();
  });
});

describe("isJwtExpired - JWT 过期检查", () => {
  it("应该返回 true 对于 null payload", () => {
    expect(isJwtExpired(null)).toBe(true);
  });

  it("应该返回 false 对于没有过期时间的 payload", () => {
    expect(isJwtExpired({ sub: "123" })).toBe(false);
  });

  it("应该返回 true 对于已过期的 payload", () => {
    const expiredPayload: JwtPayload = {
      sub: "123",
      exp: Math.floor(Date.now() / 1000) - 3600, // 1 小时前过期
    };
    expect(isJwtExpired(expiredPayload)).toBe(true);
  });

  it("应该返回 false 对于未过期的 payload", () => {
    const validPayload: JwtPayload = {
      sub: "123",
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 小时后过期
    };
    expect(isJwtExpired(validPayload)).toBe(false);
  });
});

describe("validateJwtClaims - JWT Claims 验证", () => {
  it("应该验证通过对于有效的 payload", () => {
    const payload: JwtPayload = {
      sub: "123",
      iss: "my-app",
      aud: "my-api",
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const result = validateJwtClaims(payload, {
      secret: "secret",
      issuer: "my-app",
      audience: "my-api",
    });

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("应该验证失败对于过期的 payload", () => {
    const payload: JwtPayload = {
      sub: "123",
      exp: Math.floor(Date.now() / 1000) - 100,
    };

    const result = validateJwtClaims(payload, { secret: "secret" });

    expect(result.valid).toBe(false);
    expect(result.error).toContain("过期");
  });

  it("应该验证失败对于签发者不匹配", () => {
    const payload: JwtPayload = {
      sub: "123",
      iss: "other-app",
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const result = validateJwtClaims(payload, {
      secret: "secret",
      issuer: "my-app",
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain("签发者");
  });
});

describe("extractUserFromJwt - 从 JWT 提取用户", () => {
  it("应该提取用户信息", () => {
    const payload: JwtPayload = {
      sub: "123",
      username: "admin",
      email: "admin@test.com",
      roles: ["admin", "user"],
      permissions: ["read", "write"],
    };

    const user = extractUserFromJwt(payload);

    expect(user).toBeDefined();
    expect(user!.id).toBe("123");
    expect(user!.username).toBe("admin");
    expect(user!.email).toBe("admin@test.com");
    expect(user!.roles).toEqual(["admin", "user"]);
    expect(user!.permissions).toEqual(["read", "write"]);
  });

  it("应该返回 null 对于 null payload", () => {
    expect(extractUserFromJwt(null)).toBeNull();
  });
});

describe("角色检查", () => {
  const user: AuthUser = {
    id: "123",
    roles: ["admin", "editor"],
    permissions: ["read", "write", "delete"],
  };

  describe("hasRole", () => {
    it("应该返回 true 如果用户有角色", () => {
      expect(hasRole(user, "admin")).toBe(true);
      expect(hasRole(user, "editor")).toBe(true);
    });

    it("应该返回 false 如果用户没有角色", () => {
      expect(hasRole(user, "moderator")).toBe(false);
    });

    it("应该返回 false 对于 null 用户", () => {
      expect(hasRole(null, "admin")).toBe(false);
    });
  });

  describe("hasAnyRole", () => {
    it("应该返回 true 如果用户有任意角色", () => {
      expect(hasAnyRole(user, ["admin", "moderator"])).toBe(true);
      expect(hasAnyRole(user, ["guest", "editor"])).toBe(true);
    });

    it("应该返回 false 如果用户没有任何角色", () => {
      expect(hasAnyRole(user, ["guest", "moderator"])).toBe(false);
    });
  });

  describe("hasAllRoles", () => {
    it("应该返回 true 如果用户有所有角色", () => {
      expect(hasAllRoles(user, ["admin", "editor"])).toBe(true);
    });

    it("应该返回 false 如果用户缺少任何角色", () => {
      expect(hasAllRoles(user, ["admin", "moderator"])).toBe(false);
    });
  });
});

describe("权限检查", () => {
  const user: AuthUser = {
    id: "123",
    permissions: ["users:read", "users:write", "posts:read"],
  };

  describe("hasPermission", () => {
    it("应该返回 true 如果用户有权限", () => {
      expect(hasPermission(user, "users:read")).toBe(true);
    });

    it("应该返回 false 如果用户没有权限", () => {
      expect(hasPermission(user, "users:delete")).toBe(false);
    });
  });

  describe("hasAnyPermission", () => {
    it("应该返回 true 如果用户有任意权限", () => {
      expect(hasAnyPermission(user, ["users:read", "users:delete"])).toBe(true);
    });

    it("应该返回 false 如果用户没有任何权限", () => {
      expect(hasAnyPermission(user, ["admin:all", "system:config"])).toBe(
        false,
      );
    });
  });

  describe("hasAllPermissions", () => {
    it("应该返回 true 如果用户有所有权限", () => {
      expect(hasAllPermissions(user, ["users:read", "users:write"])).toBe(true);
    });

    it("应该返回 false 如果用户缺少任何权限", () => {
      expect(hasAllPermissions(user, ["users:read", "users:delete"])).toBe(
        false,
      );
    });
  });
});

describe("matchPath - 路径匹配", () => {
  it("应该匹配精确路径", () => {
    expect(matchPath("/api/users", ["/api/users"])).toBe(true);
  });

  it("应该匹配前缀路径", () => {
    expect(matchPath("/api/users/123", ["/api/"])).toBe(true);
  });

  it("应该匹配正则表达式", () => {
    expect(matchPath("/api/users/123", [/^\/api\/users\/\d+$/])).toBe(true);
  });

  it("应该返回 false 对于不匹配的路径", () => {
    expect(matchPath("/public/file", ["/api/"])).toBe(false);
  });

  it("应该返回 false 对于 undefined 路径", () => {
    expect(matchPath(undefined, ["/api/"])).toBe(false);
  });
});

describe("requiresAuth - 认证需求检查", () => {
  it("应该返回 false 对于公开路径", () => {
    expect(
      requiresAuth("/public/file", {
        publicPaths: ["/public/"],
      }),
    ).toBe(false);
  });

  it("应该返回 true 对于受保护路径", () => {
    expect(
      requiresAuth("/api/users", {
        protectedPaths: ["/api/"],
      }),
    ).toBe(true);
  });

  it("应该返回 true 默认情况", () => {
    expect(requiresAuth("/anything", {})).toBe(true);
  });
});

describe("getRequiredRoles - 获取所需角色", () => {
  const roles = {
    "/admin": ["admin"],
    "/api/users": ["admin", "moderator"],
  };

  it("应该返回精确匹配的角色", () => {
    expect(getRequiredRoles("/admin", roles)).toEqual(["admin"]);
  });

  it("应该返回前缀匹配的角色", () => {
    expect(getRequiredRoles("/api/users/123", roles)).toEqual([
      "admin",
      "moderator",
    ]);
  });

  it("应该返回空数组对于不匹配的路径", () => {
    expect(getRequiredRoles("/public", roles)).toEqual([]);
  });
});
