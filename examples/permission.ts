/**
 * @fileoverview 权限验证示例
 *
 * 展示角色和权限的检查功能
 */

import {
  type AuthUser,
  hasAllPermissions,
  hasAllRoles,
  hasAnyPermission,
  hasAnyRole,
  hasPermission,
  hasRole,
} from "../src/mod.ts";

// ============================================================================
// 用户数据定义
// ============================================================================

console.log("=== 权限验证示例 ===\n");

// 定义用户
const adminUser: AuthUser = {
  id: "1",
  username: "admin",
  roles: ["admin", "user"],
  permissions: ["user:read", "user:write", "user:delete", "system:config"],
};

const normalUser: AuthUser = {
  id: "2",
  username: "user",
  roles: ["user"],
  permissions: ["user:read", "user:write"],
};

const guestUser: AuthUser = {
  id: "3",
  username: "guest",
  roles: ["guest"],
  permissions: ["user:read"],
};

// ============================================================================
// 角色检查
// ============================================================================

console.log("=== 角色检查 ===\n");

console.log("Admin 用户:");
console.log("  是否有 admin 角色:", hasRole(adminUser, "admin"));
console.log("  是否有 user 角色:", hasRole(adminUser, "user"));
console.log("  是否有 super 角色:", hasRole(adminUser, "super"));

console.log("\n普通用户:");
console.log("  是否有 admin 角色:", hasRole(normalUser, "admin"));
console.log("  是否有 user 角色:", hasRole(normalUser, "user"));

// ============================================================================
// 多角色检查
// ============================================================================

console.log("\n=== 多角色检查 ===\n");

// 是否拥有任意一个角色
console.log(
  "Admin 是否有 admin 或 moderator:",
  hasAnyRole(adminUser, ["admin", "moderator"]),
);
console.log(
  "Guest 是否有 admin 或 moderator:",
  hasAnyRole(guestUser, ["admin", "moderator"]),
);

// 是否拥有所有角色
console.log(
  "\nAdmin 是否同时有 admin 和 user:",
  hasAllRoles(adminUser, ["admin", "user"]),
);
console.log(
  "Admin 是否同时有 admin 和 super:",
  hasAllRoles(adminUser, ["admin", "super"]),
);

// ============================================================================
// 权限检查
// ============================================================================

console.log("\n=== 权限检查 ===\n");

console.log("Admin 用户权限:");
console.log("  user:read:", hasPermission(adminUser, "user:read"));
console.log("  user:delete:", hasPermission(adminUser, "user:delete"));
console.log("  system:config:", hasPermission(adminUser, "system:config"));

console.log("\n普通用户权限:");
console.log("  user:read:", hasPermission(normalUser, "user:read"));
console.log("  user:delete:", hasPermission(normalUser, "user:delete"));
console.log("  system:config:", hasPermission(normalUser, "system:config"));

console.log("\n游客权限:");
console.log("  user:read:", hasPermission(guestUser, "user:read"));
console.log("  user:write:", hasPermission(guestUser, "user:write"));

// ============================================================================
// 多权限检查
// ============================================================================

console.log("\n=== 多权限检查 ===\n");

// 任意一个权限
console.log(
  "Admin 有读或删除权限:",
  hasAnyPermission(adminUser, ["user:read", "user:delete"]),
);
console.log(
  "Guest 有读或删除权限:",
  hasAnyPermission(guestUser, ["user:read", "user:delete"]),
);
console.log(
  "Guest 有写或删除权限:",
  hasAnyPermission(guestUser, ["user:write", "user:delete"]),
);

// 所有权限
console.log(
  "\nAdmin 同时有读和写权限:",
  hasAllPermissions(adminUser, ["user:read", "user:write"]),
);
console.log(
  "Normal 同时有读、写、删除权限:",
  hasAllPermissions(normalUser, ["user:read", "user:write", "user:delete"]),
);

// ============================================================================
// 认证守卫函数
// ============================================================================

console.log("\n=== 认证守卫函数 ===\n");

/**
 * 创建角色守卫
 *
 * @param requiredRoles - 需要的角色列表
 * @param requireAll - 是否需要所有角色
 * @returns 守卫函数
 */
function createRoleGuard(requiredRoles: string[], requireAll = false) {
  return (user: AuthUser | null): boolean => {
    if (!user) return false;
    return requireAll
      ? hasAllRoles(user, requiredRoles)
      : hasAnyRole(user, requiredRoles);
  };
}

/**
 * 创建权限守卫
 *
 * @param requiredPermissions - 需要的权限列表
 * @param requireAll - 是否需要所有权限
 * @returns 守卫函数
 */
function createPermissionGuard(
  requiredPermissions: string[],
  requireAll = false,
) {
  return (user: AuthUser | null): boolean => {
    if (!user) return false;
    return requireAll
      ? hasAllPermissions(user, requiredPermissions)
      : hasAnyPermission(user, requiredPermissions);
  };
}

// 创建角色守卫
const adminGuard = createRoleGuard(["admin"]);

// 创建权限守卫
const deleteGuard = createPermissionGuard(["user:delete"]);

// 创建组合守卫
const systemGuard = (user: AuthUser | null): boolean => {
  return hasRole(user, "admin") && hasPermission(user, "system:config");
};

console.log("Admin 守卫检查:");
console.log("  adminUser:", adminGuard(adminUser));
console.log("  normalUser:", adminGuard(normalUser));

console.log("\n删除权限守卫检查:");
console.log("  adminUser:", deleteGuard(adminUser));
console.log("  normalUser:", deleteGuard(normalUser));

console.log("\n系统配置守卫检查:");
console.log("  adminUser:", systemGuard(adminUser));
console.log("  normalUser:", systemGuard(normalUser));

// ============================================================================
// 实际应用示例
// ============================================================================

console.log("\n=== 实际应用示例 ===\n");

/**
 * 模拟 API 路由处理
 *
 * @param user - 当前用户
 * @param action - 要执行的操作
 */
function handleUserAction(user: AuthUser | null, action: string): void {
  if (!user) {
    console.log(`[${action}] 未登录，拒绝访问`);
    return;
  }

  switch (action) {
    case "view":
      if (hasPermission(user, "user:read")) {
        console.log(`[${action}] ${user.username} 可以查看用户列表`);
      } else {
        console.log(`[${action}] ${user.username} 没有查看权限`);
      }
      break;

    case "edit":
      if (hasPermission(user, "user:write")) {
        console.log(`[${action}] ${user.username} 可以编辑用户`);
      } else {
        console.log(`[${action}] ${user.username} 没有编辑权限`);
      }
      break;

    case "delete":
      if (hasRole(user, "admin") && hasPermission(user, "user:delete")) {
        console.log(`[${action}] ${user.username} 可以删除用户`);
      } else {
        console.log(
          `[${action}] ${user.username} 没有删除权限（需要 admin 角色）`,
        );
      }
      break;

    case "config":
      if (systemGuard(user)) {
        console.log(`[${action}] ${user.username} 可以修改系统配置`);
      } else {
        console.log(`[${action}] ${user.username} 没有系统配置权限`);
      }
      break;

    default:
      console.log(`[${action}] 未知操作`);
  }
}

// 测试不同用户的权限
const actions = ["view", "edit", "delete", "config"];

console.log("--- Admin 用户 ---");
for (const action of actions) {
  handleUserAction(adminUser, action);
}

console.log("\n--- 普通用户 ---");
for (const action of actions) {
  handleUserAction(normalUser, action);
}

console.log("\n--- 游客 ---");
for (const action of actions) {
  handleUserAction(guestUser, action);
}

// ============================================================================
// 中间件示例
// ============================================================================

console.log("\n=== 中间件示例 ===\n");

console.log(`
// Oak 中间件示例
import { Context, Next } from "oak";

// 角色检查中间件
function requireRole(...roles: string[]) {
  return async (ctx: Context, next: Next) => {
    const user = ctx.state.user as AuthUser | null;
    
    if (!user || !hasAnyRole(user, roles)) {
      ctx.response.status = 403;
      ctx.response.body = { error: "Forbidden" };
      return;
    }
    
    await next();
  };
}

// 权限检查中间件
function requirePermission(...permissions: string[]) {
  return async (ctx: Context, next: Next) => {
    const user = ctx.state.user as AuthUser | null;
    
    if (!user || !hasAllPermissions(user, permissions)) {
      ctx.response.status = 403;
      ctx.response.body = { error: "Forbidden" };
      return;
    }
    
    await next();
  };
}

// 使用中间件
router.delete("/users/:id", requireRole("admin"), requirePermission("user:delete"), async (ctx) => {
  // 只有 admin 角色且有 user:delete 权限的用户才能访问
  await deleteUser(ctx.params.id);
  ctx.response.body = { success: true };
});
`);
