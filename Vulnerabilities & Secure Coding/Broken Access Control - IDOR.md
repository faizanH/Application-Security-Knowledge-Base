## 🧠 Description

- **What it is (simple + technical)**:  
  Broken Access Control occurs when users can access or perform actions they shouldn’t be allowed to.  
  In simple terms, a user can access another user's data, perform admin actions, or change something they don't own — usually by modifying a URL, body param, or cookie.

- **Where it occurs**:  
  In the **backend/API layer**, which is responsible for enforcing authorization. It’s common in APIs, admin panels, user profile routes, and file access endpoints.

- **Root cause**:  
  The application **fails to properly enforce authorization logic** based on role, identity, or ownership. Often, it **relies on untrusted input** (e.g. user ID in request body or URL).

- **Common subtypes**:
  - **IDOR (Insecure Direct Object Reference)**:  
    User accesses someone else's resource by guessing or modifying an object ID (e.g., `/invoices/1002`).

  - **Vertical privilege escalation**:  
    A user performs actions that only admins or higher-privileged users should be allowed to.

  - **Horizontal privilege escalation**:  
    A user accesses or modifies another user's data at the same privilege level.

  - **Missing method or role-level checks**:  
    APIs like `PUT /users/:id/role` are exposed without checking if the requester is an admin.

---

## 🧪 Exploitation Techniques

- **IDOR Exploitation Example**:
  1. Alice logs in and views:
     ```
     GET /api/invoices/101
     ```
  2. Alice changes the URL:
     ```
     GET /api/invoices/102
     ```
  3. If invoice 102 belongs to another user and still loads — the API is vulnerable.

- **Common attack patterns**:
  - Changing a URL path param:
    ```
    /api/users/123 → /api/users/1
    ```
  - Injecting identity fields in JSON:
    ```json
    { "userId": 1 }
    ```
  - Overriding cookies or headers:
    ```
    Cookie: user_role=admin
    ```

- **Tools used**:
  - Burp Suite (Repeater, Intruder)
  - Postman / curl
  - Proxy tools and browser DevTools
  - jwt.io (for decoding/modifying JWTs)

- **Real-world examples**:
  - **Snapchat (2014)**: Mass IDOR leaks from contact lookup API
  - **Uber (2016)**: Drivers accessed customer data due to improper access checks
  - **Facebook Graph API bugs**: Allowed impersonation and content posting

---

## 🔎 Code Review Tips

- **🚫 Never trust user-supplied identity fields**:
  - ❌ `req.body.userId`
  - ❌ `req.params.userId`
  - ❌ `req.query.userId`
  - These values come directly from the attacker and **must not be used** for authorization.

- ✅ Use identity derived from **authenticated sources**:
  - Session-based: `req.session.user.id`
  - JWT-based: `req.user.id` (populated from a validated token)
  - Middleware injection: Set trusted identity after verification

- **Bad vs Good Examples**:

  - ❌ **Bad - TypeScript (trusts attacker-controlled input)**
    ```ts
    // Attacker can spoof any user ID
    app.get("/users/:id", (req, res) => {
      const user = db.findUserById(req.params.id);
      res.send(user);
    });
    ```

  - ✅ **Good - TypeScript (uses trusted identity from middleware)**
    ```ts
    app.use(authMiddleware); // Sets req.user securely

    app.get("/users/:id", async (req, res) => {
      const requestedId = req.params.id;

      // ✅ Ensure the logged-in user is only accessing their own data
      if (requestedId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).send("Forbidden");
      }

      const user = await db.findUserById(requestedId);
      res.send(user);
    });
    ```

  - ✅ **Good - Python (Flask with secure session)**
    ```python
    @app.route("/profile/<user_id>")
    def profile(user_id):
        if user_id != session.get("user_id"):
            abort(403)
        return db.get_user(user_id)
    ```

- **Where to look**:
  - Any route that references a user ID, account ID, or object ID
  - `PUT`, `PATCH`, `DELETE` endpoints
  - Role elevation paths (e.g., `POST /users/role`)
  - Admin panels or hidden features

---

## 🛡️ Mitigation Strategies

- **✅ Enforce ownership + role checks**:
  - Confirm the authenticated user **owns the resource** or has the required role
  - Never trust `req.body.userId`, `req.params.userId`, etc.

- **✅ Authenticate and inject identity securely**:
  Use one of the following trusted mechanisms:

---

### 🔐 Auth Mechanisms That Can Be Trusted

#### 1. **Signed session (cookie-based)**

- Server sets a signed cookie after login:
  ```
  Set-Cookie: session_id=abc123; HttpOnly; Secure
  ```
- On each request:
  - Server looks up the session and sets `req.session.user`

- ✅ Safe, easy to implement
- 🔁 Requires sticky sessions or shared store (Redis, DB)

---

#### 2. **Validated JWT (stateless auth)**

- Client stores a JWT (JSON Web Token) signed by the backend:
  ```
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI...
  ```
- Middleware verifies the JWT signature and sets:
  ```ts
  req.user = {
    id: decoded.sub,
    role: decoded.role,
  };
  ```

- ✅ Scalable and stateless
- ❗ Must validate signature and expiration!

---

#### 3. **API key with scopes**

- Backend APIs use API keys or tokens tied to a scope:
  ``` 
  X-API-Key: abc123
  ```
- Key maps to a service or user identity with roles:
  ```ts
  req.user = {
    id: "integration-789",
    scopes: ["read:users", "write:invoices"]
  };
  ```

- ✅ Good for service-to-service auth
- ❗ Still need access enforcement based on scope

---

## ✅ Other Mitigations

- **Centralize access control logic**  
  Create an `authorize(user, action, object)` function or middleware for consistency.

- **Use libraries or RBAC frameworks**:  
  `casbin`, `node-casbin`, `django-guardian`, `pundit`

- **Deny by default**  
  Design routes and policies that require explicit access grants.

- **Log and alert access violations**  
  Track 403s, suspicious ID access patterns, brute force on object IDs

- **Rate limit APIs**  
  Prevent rapid object ID scanning or role escalation attempts

---

## 🔐 Blockchain Context (if applicable)

- **Smart contracts**:  
  Broken access control on-chain = anyone can call `withdraw()`, `mint()`, `transferOwnership()`  
  Always enforce `onlyOwner`, `require(msg.sender == ...)` in contracts

- **Web3 backends**:
  - Protect off-chain APIs (e.g., fetching wallet or NFT metadata)
  - Use wallet signature verification (e.g., EIP-4361 "Sign-In with Ethereum") to authenticate users
  - Don’t trust addresses passed in the body — verify the signer!

---
