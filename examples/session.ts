/**
 * @fileoverview Session 会话管理示例
 *
 * 展示 Session 的创建、验证、销毁等功能
 *
 * 注意：此示例展示 API 用法，实际运行需要 @dreamer/session 依赖
 */

// ============================================================================
// Session 管理示例代码
// ============================================================================

console.log("=== Session 管理示例 ===\n");

console.log(`
// 导入依赖
import { AuthSessionManager, type HttpContext } from "@dreamer/auth";
import { MemorySessionStore } from "@dreamer/session";

// 创建 Session 存储（生产环境建议使用 Redis）
const store = new MemorySessionStore();

// 创建 Session 管理器
const session = new AuthSessionManager({
  store,
  cookieName: "sessionId",
  maxAge: 24 * 60 * 60 * 1000, // 24 小时
  cookie: {
    httpOnly: true,
    secure: false, // 开发环境设为 false
    sameSite: "lax",
  },
});
`);

// ============================================================================
// 用户登录
// ============================================================================

console.log("=== 用户登录 ===\n");

console.log(`
// 模拟用户数据
const user = {
  id: "12345",
  username: "admin",
  email: "admin@example.com",
  roles: ["admin", "user"],
};

// 登录（创建 Session）
await session.login(ctx, user);
console.log("登录成功！");
`);

// ============================================================================
// 加载 Session
// ============================================================================

console.log("=== 加载 Session ===\n");

console.log(`
// 加载 Session（通常在中间件中调用）
const loaded = await session.loadSession(ctx);

if (loaded) {
  console.log("Session 加载成功");
  console.log("Session 数据:", ctx.session);
} else {
  console.log("没有找到有效的 Session");
}
`);

// ============================================================================
// 检查认证状态
// ============================================================================

console.log("=== 检查认证状态 ===\n");

console.log(`
// 检查是否已认证
const isAuth = await session.isAuthenticated(ctx);
console.log("是否已认证:", isAuth);

// 获取当前用户
const currentUser = await session.getUser(ctx);
if (currentUser) {
  console.log("当前用户:", currentUser.username);
  console.log("用户角色:", currentUser.roles);
}
`);

// ============================================================================
// 更新 Session
// ============================================================================

console.log("=== 更新 Session ===\n");

console.log(`
// 更新 Session 数据
await session.touch(ctx); // 更新最后活动时间

// 刷新 Session（生成新的 Session ID）
await session.regenerate(ctx);
console.log("Session 已刷新");
`);

// ============================================================================
// 用户登出
// ============================================================================

console.log("=== 用户登出 ===\n");

console.log(`
// 登出（销毁 Session）
await session.logout(ctx);
console.log("登出成功！");

// 验证登出后状态
const isAuthAfterLogout = await session.isAuthenticated(ctx);
console.log("登出后是否已认证:", isAuthAfterLogout); // false
`);

// ============================================================================
// 自定义序列化
// ============================================================================

console.log("=== 自定义序列化 ===\n");

console.log(`
// 创建带自定义序列化的 Session 管理器
const customSession = new AuthSessionManager({
  store: new MemorySessionStore(),
  
  // 只存储用户 ID，减少存储空间
  serializeUser: (user: AuthUser) => ({ id: user.id }),
  
  // 从数据库加载完整用户信息
  deserializeUser: async (data: AuthUser) => {
    // 模拟数据库查询
    const fullUser = await db.users.findById(data.id);
    return fullUser;
  },
});
`);

// ============================================================================
// 中间件示例
// ============================================================================

console.log("=== 中间件示例 ===\n");

console.log(`
// Oak 中间件示例
import { Application, Context, Next } from "oak";

// Session 中间件
async function sessionMiddleware(ctx: Context, next: Next) {
  // 加载 Session
  await session.loadSession(ctx);
  
  await next();
}

// 认证保护中间件
async function authMiddleware(ctx: Context, next: Next) {
  if (!await session.isAuthenticated(ctx)) {
    ctx.response.status = 401;
    ctx.response.body = { error: "Unauthorized" };
    return;
  }
  
  await next();
}

// 使用中间件
const app = new Application();

app.use(sessionMiddleware);

router.get("/protected", authMiddleware, async (ctx) => {
  const user = await session.getUser(ctx);
  ctx.response.body = { user };
});

app.use(router.routes());
`);

// ============================================================================
// HttpContext 接口说明
// ============================================================================

console.log("=== HttpContext 接口说明 ===\n");

console.log(`
// HttpContext 接口定义
interface HttpContext {
  // Cookie 操作
  cookies: {
    get(name: string): string | undefined;
    set(name: string, value: string, options?: CookieOptions): void;
    delete(name: string): void;
  };
  
  // Session 数据（由 loadSession 填充）
  session?: AuthSessionData;
}

// 大多数 Web 框架的 Context 都兼容此接口
// Oak、Hono、Fresh 等都可以直接使用
`);
