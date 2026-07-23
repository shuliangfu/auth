# @dreamer/auth Test Report

## 📊 Test Overview

| Item                | Value                              |
| ------------------- | ---------------------------------- |
| **Package version** | `@dreamer/auth@1.1.0`             |
| **Crypto package**  | `@dreamer/crypto@^1.1.0`          |
| **Session package** | `@dreamer/session@^1.1.0`         |
| **Test framework**  | `@dreamer/test@^1.2.3`            |
| **Test date**       | `2026-07-23`                       |
| **Environment**     | Deno 2.9+, Bun 1.3+, Node.js 22+  |

---

## 🎯 Test Results

### Overall Statistics

| Metric             | Deno | Bun   | Node.js |
| ------------------ | ---- | ----- | ------- |
| **Total tests**    | 128  | 123   | 123     |
| **Passed**         | 128  | 123   | 123     |
| **Failed**         | 0    | 0     | 0       |
| **Pass rate**      | 100% | 100%  | 100%    |
| **Execution time** | ~6s  | ~4.6s | ~5s     |

> Deno counts 5 additional lifecycle hooks (`describe` `afterAll` + `@dreamer/test`
> cleanup) on top of the 123 unit tests; Bun and Node.js report 123 unit tests
> each.

### Test File Statistics

| Test file         | Count | Passed | Failed | Status  |
| ----------------- | ----- | ------ | ------ | ------- |
| `jwt.test.ts`     | 22    | 22     | 0      | ✅ Pass |
| `mod.test.ts`     | 45    | 45     | 0      | ✅ Pass |
| `oauth.test.ts`   | 22    | 22     | 0      | ✅ Pass |
| `refresh.test.ts` | 15    | 15     | 0      | ✅ Pass |
| `session.test.ts` | 24    | 24     | 0      | ✅ Pass |

---

## 📋 Functional Test Details

### 1. JWT Signing and Verification (jwt.test.ts) - 22 tests

#### signToken - JWT Signing (3 tests)

| Test scenario                           | Status |
| --------------------------------------- | ------ |
| Should sign JWT with HS256              | ✅     |
| Should include correct payload          | ✅     |
| Should support different expiry formats | ✅     |

#### verifyToken - JWT Verification (4 tests)

| Test scenario               | Status |
| --------------------------- | ------ |
| Should verify valid JWT     | ✅     |
| Should reject wrong key     | ✅     |
| Should reject expired Token | ✅     |
| Should verify issuer        | ✅     |

#### decodeToken - JWT Decode (2 tests)

| Test scenario                        | Status |
| ------------------------------------ | ------ |
| Should decode JWT Header and Payload | ✅     |
| Should throw on invalid Token format | ✅     |

#### isTokenExpired - Expiry Check (3 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should return false for non-expired Token | ✅     |
| Should return true for expired Token      | ✅     |
| Should return true for invalid Token      | ✅     |

#### getTokenExpiration - Get Expiration Time (2 tests)

| Test scenario                               | Status |
| ------------------------------------------- | ------ |
| Should return expiration timestamp          | ✅     |
| Should return null for Token without expiry | ✅     |

#### getTokenRemainingTime - Get Remaining Time (3 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should return correct remaining time      | ✅     |
| Should return 0 for expired Token         | ✅     |
| Should return -1 for Token without expiry | ✅     |

#### generateRSAKeyPair - RSA Key Pair Generation (2 tests)

| Test scenario                       | Status |
| ----------------------------------- | ------ |
| Should generate RSA key pair        | ✅     |
| Should sign and verify with RSA key | ✅     |

#### generateECKeyPair - ECDSA Key Pair Generation (2 tests)

| Test scenario                         | Status |
| ------------------------------------- | ------ |
| Should generate ECDSA key pair        | ✅     |
| Should sign and verify with ECDSA key | ✅     |

---

### 2. Auth Utility Functions (mod.test.ts) - 45 tests

#### parseBearerToken - Bearer Token Parsing (4 tests)

| Test scenario                            | Status |
| ---------------------------------------- | ------ |
| Should parse valid Bearer Token          | ✅     |
| Should return null for null input        | ✅     |
| Should return null for non-Bearer prefix | ✅     |
| Should return null for empty string      | ✅     |

#### parseBasicAuth - Basic Auth Parsing (3 tests)

| Test scenario                        | Status |
| ------------------------------------ | ------ |
| Should parse valid Basic Auth        | ✅     |
| Should handle password with colon    | ✅     |
| Should return null for invalid input | ✅     |

#### createBasicAuthHeader - Basic Auth Header Generation (1 test)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should generate correct Basic Auth header | ✅     |

#### createBearerAuthHeader - Bearer Auth Header Generation (1 test)

| Test scenario                              | Status |
| ------------------------------------------ | ------ |
| Should generate correct Bearer Auth header | ✅     |

#### parseJwt - JWT Parsing (2 tests)

| Test scenario                        | Status |
| ------------------------------------ | ------ |
| Should parse valid JWT               | ✅     |
| Should return null for invalid Token | ✅     |

#### isJwtExpired - JWT Expiry Check (4 tests)

| Test scenario                                  | Status |
| ---------------------------------------------- | ------ |
| Should return true for null payload            | ✅     |
| Should return false for payload without expiry | ✅     |
| Should return true for expired payload         | ✅     |
| Should return false for non-expired payload    | ✅     |

#### validateJwtClaims - JWT Claims Validation (3 tests)

| Test scenario                   | Status |
| ------------------------------- | ------ |
| Should pass for valid payload   | ✅     |
| Should fail for expired payload | ✅     |
| Should fail for issuer mismatch | ✅     |

#### extractUserFromJwt - Extract User from JWT (2 tests)

| Test scenario                       | Status |
| ----------------------------------- | ------ |
| Should extract user info            | ✅     |
| Should return null for null payload | ✅     |

#### Role check - hasRole (3 tests)

| Test scenario                           | Status |
| --------------------------------------- | ------ |
| Should return true if user has role     | ✅     |
| Should return false if user has no role | ✅     |
| Should return false for null user       | ✅     |

#### Role check - hasAnyRole (2 tests)

| Test scenario                            | Status |
| ---------------------------------------- | ------ |
| Should return true if user has any role  | ✅     |
| Should return false if user has no roles | ✅     |

#### Role check - hasAllRoles (2 tests)

| Test scenario                              | Status |
| ------------------------------------------ | ------ |
| Should return true if user has all roles   | ✅     |
| Should return false if user lacks any role | ✅     |

#### Permission check - hasPermission (2 tests)

| Test scenario                                 | Status |
| --------------------------------------------- | ------ |
| Should return true if user has permission     | ✅     |
| Should return false if user has no permission | ✅     |

#### Permission check - hasAnyPermission (2 tests)

| Test scenario                                  | Status |
| ---------------------------------------------- | ------ |
| Should return true if user has any permission  | ✅     |
| Should return false if user has no permissions | ✅     |

#### Permission check - hasAllPermissions (2 tests)

| Test scenario                                    | Status |
| ------------------------------------------------ | ------ |
| Should return true if user has all permissions   | ✅     |
| Should return false if user lacks any permission | ✅     |

#### matchPath - Path Matching (5 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should match exact path                   | ✅     |
| Should match prefix path                  | ✅     |
| Should match regex                        | ✅     |
| Should return false for non-matching path | ✅     |
| Should return false for undefined path    | ✅     |

#### requiresAuth - Auth Requirement Check (3 tests)

| Test scenario                         | Status |
| ------------------------------------- | ------ |
| Should return false for public path   | ✅     |
| Should return true for protected path | ✅     |
| Should return true by default         | ✅     |

#### getRequiredRoles - Get Required Roles (3 tests)

| Test scenario                                   | Status |
| ----------------------------------------------- | ------ |
| Should return exactly matched roles             | ✅     |
| Should return prefix-matched roles              | ✅     |
| Should return empty array for non-matching path | ✅     |

---

### 3. OAuth 2.0 Client (oauth.test.ts) - 22 tests

#### generatePKCE - PKCE Parameter Generation (2 tests)

| Test scenario                                    | Status |
| ------------------------------------------------ | ------ |
| Should generate code_verifier and code_challenge | ✅     |
| Should generate different PKCE params each time  | ✅     |

#### generateState - State Parameter Generation (2 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should generate random state string       | ✅     |
| Should generate different state each time | ✅     |

#### OAuth2Client - Client (5 tests)

| Test scenario                     | Status |
| --------------------------------- | ------ |
| Should generate authorization URL | ✅     |
| Should support custom scope       | ✅     |
| Should support state parameter    | ✅     |
| Should support PKCE               | ✅     |
| Should support extra parameters   | ✅     |

#### Built-in Provider Configuration (5 tests)

| Test scenario                                 | Status |
| --------------------------------------------- | ------ |
| GitHub Provider should have correct endpoints | ✅     |
| Google Provider should have correct endpoints | ✅     |
| WeChat Provider should have correct endpoints | ✅     |
| GitLab Provider should have correct endpoints | ✅     |
| Gitee Provider should have correct endpoints  | ✅     |

#### User Info Parsers (4 tests)

| Test scenario                          | Status |
| -------------------------------------- | ------ |
| parseGitHubUser should parse correctly | ✅     |
| parseGoogleUser should parse correctly | ✅     |
| parseGitLabUser should parse correctly | ✅     |
| parseGiteeUser should parse correctly  | ✅     |

#### Factory Functions (3 tests)

| Test scenario                                  | Status |
| ---------------------------------------------- | ------ |
| createOAuth2Client should create client        | ✅     |
| createGitHubClient should create GitHub client | ✅     |
| createGoogleClient should create Google client | ✅     |

---

### 4. Token Refresh Management (refresh.test.ts) - 15 tests

#### MemoryTokenStore - In-Memory Store (5 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should save and get Token                 | ✅     |
| Should return null for non-existent Token | ✅     |
| Should delete Token                       | ✅     |
| Should delete all Tokens by user          | ✅     |
| Should return null for expired Token      | ✅     |

#### TokenManager - Token Manager (8 tests)

| Test scenario                                 | Status |
| --------------------------------------------- | ------ |
| Should generate Token pair                    | ✅     |
| Should verify Access Token                    | ✅     |
| Should refresh Token                          | ✅     |
| Should reject already-refreshed Refresh Token | ✅     |
| Should revoke Refresh Token                   | ✅     |
| Should revoke all Tokens for user             | ✅     |
| Should check if Token needs refresh           | ✅     |
| Should check if Token is expired              | ✅     |

#### createTokenManager - Factory (1 test)

| Test scenario                       | Status |
| ----------------------------------- | ------ |
| Should create TokenManager instance | ✅     |

---

### 5. Auth Session Management (session.test.ts) - 24 tests

#### AuthSessionManager - login (2 tests)

| Test scenario                        | Status |
| ------------------------------------ | ------ |
| Should create Session and set Cookie | ✅     |
| Should store Session in store        | ✅     |

#### AuthSessionManager - logout (2 tests)

| Test scenario                      | Status |
| ---------------------------------- | ------ |
| Should delete Session and Cookie   | ✅     |
| Should handle unauthenticated case | ✅     |

#### AuthSessionManager - isAuthenticated (3 tests)

| Test scenario                                | Status |
| -------------------------------------------- | ------ |
| Should return true for authenticated user    | ✅     |
| Should return false for unauthenticated user | ✅     |
| Should return false after logout             | ✅     |

#### AuthSessionManager - getUser (2 tests)

| Test scenario                               | Status |
| ------------------------------------------- | ------ |
| Should return authenticated user info       | ✅     |
| Should return null for unauthenticated user | ✅     |

#### AuthSessionManager - loadSession (4 tests)

| Test scenario                                            | Status |
| -------------------------------------------------------- | ------ |
| Should load Session from Cookie                          | ✅     |
| Should return false for request without Cookie           | ✅     |
| Should return false and clear Cookie for invalid Session | ✅     |
| Should update last activity time                         | ✅     |

#### AuthSessionManager - middleware (2 tests)

| Test scenario                    | Status |
| -------------------------------- | ------ |
| Should auto-load Session         | ✅     |
| Should call next when no Session | ✅     |

#### AuthSessionManager - requireAuth (3 tests)

| Test scenario                                     | Status |
| ------------------------------------------------- | ------ |
| Should allow authenticated user through           | ✅     |
| Should return 401 for unauthenticated user        | ✅     |
| Should redirect unauthenticated user to given URL | ✅     |

#### createAuthSession - Factory (2 tests)

| Test scenario                             | Status |
| ----------------------------------------- | ------ |
| Should create AuthSessionManager instance | ✅     |
| Should use custom config                  | ✅     |

#### User Serialization (3 tests)

| Test scenario                           | Status |
| --------------------------------------- | ------ |
| Should support custom serialize         | ✅     |
| Should support custom deserialize       | ✅     |
| Should delete Session when user missing | ✅     |

---

## 📈 Test Coverage Analysis

### API Method Coverage

| Module       | Method / Feature         | Coverage |
| ------------ | ------------------------ | -------- |
| `jwt.ts`     | `signToken`              | ✅       |
| `jwt.ts`     | `verifyToken`            | ✅       |
| `jwt.ts`     | `decodeToken`            | ✅       |
| `jwt.ts`     | `isTokenExpired`         | ✅       |
| `jwt.ts`     | `getTokenExpiration`     | ✅       |
| `jwt.ts`     | `getTokenRemainingTime`  | ✅       |
| `jwt.ts`     | `generateRSAKeyPair`     | ✅       |
| `jwt.ts`     | `generateECKeyPair`      | ✅       |
| `mod.ts`     | `parseBearerToken`       | ✅       |
| `mod.ts`     | `parseBasicAuth`         | ✅       |
| `mod.ts`     | `createBasicAuthHeader`  | ✅       |
| `mod.ts`     | `createBearerAuthHeader` | ✅       |
| `mod.ts`     | `parseJwt`               | ✅       |
| `mod.ts`     | `isJwtExpired`           | ✅       |
| `mod.ts`     | `validateJwtClaims`      | ✅       |
| `mod.ts`     | `extractUserFromJwt`     | ✅       |
| `mod.ts`     | `hasRole`                | ✅       |
| `mod.ts`     | `hasAnyRole`             | ✅       |
| `mod.ts`     | `hasAllRoles`            | ✅       |
| `mod.ts`     | `hasPermission`          | ✅       |
| `mod.ts`     | `hasAnyPermission`       | ✅       |
| `mod.ts`     | `hasAllPermissions`      | ✅       |
| `mod.ts`     | `matchPath`              | ✅       |
| `mod.ts`     | `requiresAuth`           | ✅       |
| `mod.ts`     | `getRequiredRoles`       | ✅       |
| `oauth.ts`   | `generatePKCE`           | ✅       |
| `oauth.ts`   | `generateState`          | ✅       |
| `oauth.ts`   | `OAuth2Client`           | ✅       |
| `oauth.ts`   | `createOAuth2Client`     | ✅       |
| `oauth.ts`   | `createGitHubClient`     | ✅       |
| `oauth.ts`   | `createGoogleClient`     | ✅       |
| `refresh.ts` | `MemoryTokenStore`       | ✅       |
| `refresh.ts` | `TokenManager`           | ✅       |
| `refresh.ts` | `createTokenManager`     | ✅       |
| `session.ts` | `AuthSessionManager`     | ✅       |
| `session.ts` | `createAuthSession`      | ✅       |

### Edge Case Coverage

| Scenario                     | Coverage |
| ---------------------------- | -------- |
| null/undefined input         | ✅       |
| Empty string handling        | ✅       |
| Invalid Token format         | ✅       |
| Expired Token handling       | ✅       |
| Wrong key verification       | ✅       |
| Non-existent Session         | ✅       |
| User without role/permission | ✅       |
| Path mismatch                | ✅       |

### Error Handling Coverage

| Scenario                           | Coverage |
| ---------------------------------- | -------- |
| Invalid Token throws error         | ✅       |
| Verification failure returns null  | ✅       |
| Expired Token rejected             | ✅       |
| Used Refresh Token rejected        | ✅       |
| Unauthenticated user returns 401   | ✅       |
| Issuer mismatch verification fails | ✅       |

---

## ✨ Strengths

1. **Full JWT support**: HS256, RS256, ES256 and more; signing, verification,
   decode.
2. **Flexible OAuth 2.0**: Built-in GitHub, Google, WeChat, GitLab, Gitee
   providers; PKCE support.
3. **Token refresh**: Access Token + Refresh Token with revocation.
4. **Session integration**: Deep integration with `@dreamer/session`; login,
   logout, auth check.
5. **Permission checks**: Role and permission checks; path matching and auth
   requirement config.
6. **Cross-runtime**: Compatible with Deno 2.9+, Bun 1.3+, and Node.js 22+.

---

## 📝 Conclusion

All 123 unit tests of @dreamer/auth pass on Deno 2.9+, Bun 1.3+, and Node.js
22+. Coverage includes JWT signing/verification, OAuth 2.0 client, Token
refresh, auth session management, and permission checks. The package provides a
complete auth solution with multiple auth methods and OAuth providers, and
cross-platform compatibility is verified across all three runtimes.

---

<div align="center">

**Pass rate: 100%** ✅

_123 unit tests | Deno 128 (incl. lifecycle) | Bun 123 | Node.js 123_

</div>
