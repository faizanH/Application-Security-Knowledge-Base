## 🧠 Description

- **What it is (simple + technical)**:  
  SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries an application makes to its database.  
  In simple terms, it happens when user input is sent to a SQL database without being properly validated or sanitized, allowing the attacker to inject malicious SQL commands.

- **Where it occurs**:  
  Typically in the **backend** — in server-side code that builds SQL queries using user input. It can also occur in APIs and legacy mobile apps that talk to a backend.

- **Root cause**:  
  The root cause is **untrusted input** being directly concatenated into SQL statements. This happens when input isn't properly escaped, validated, or parameterized.

- **The different types**:
  - **Classic SQL Injection (Error-based)**:  
    The application returns detailed database error messages. These messages help attackers extract database information by injecting malformed input and reading the returned error (e.g., table names, column names).

  - **Union-based SQL Injection**:  
    This technique uses the `UNION` SQL operator to combine results of two or more `SELECT` statements. It allows the attacker to fetch data from other tables and append it to the original query's output.

  - **Blind SQL Injection**:  
    In cases where the application does not show error messages or query results, attackers infer information based on **true/false responses** or **timing**.
    - **Boolean-based Blind**: Injecting payloads that return different app behavior depending on a true/false condition.
    - **Time-based Blind**: Injecting a query that delays the response (e.g., using `SLEEP(5)`) when a condition is true.

  - **Out-of-band SQL Injection (OOB)**:  
    Used when no data is returned to the attacker directly, but the database can send data through a different channel (like DNS or HTTP requests). This is only possible when specific database features are enabled.

---

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough**:
  1. Attacker finds an input field (e.g., login form, search box).
  2. They inject SQL payloads like `' OR '1'='1` to see if the query behavior changes.
  3. If the backend returns unusual results or errors, it's likely vulnerable.
  4. Escalation can involve dumping tables, bypassing login, or reading/writing files.

- **Payload examples**:
  - `' OR '1'='1' --`  
  - `' UNION SELECT null, username, password FROM users --`  
  - `1' AND (SELECT COUNT(*) FROM users) > 0 --`  
  - `1' OR IF(1=1, SLEEP(5), 0) --`

- **Tools used**:
  - Burp Suite (Intruder, Repeater)
  - sqlmap
  - curl or Postman (for manual testing)
  - Browser Dev Tools + Proxy Tools

- **Real-world examples**:
  - CVE-2022-0492: SQLi in OpenCATS
  - Heartland Payment Systems breach (2008)
  - TalkTalk UK breach (2015)

---

## 🔎 Code Review Tips

- **Patterns/red flags**:
  - Python: `query = "SELECT * FROM users WHERE name = '" + user_input + "'"`
  - TypeScript: `connection.query("SELECT * FROM users WHERE name = '" + userInput + "'")`

- **Bad vs Good Examples**:

  - ❌ **Bad - Python**
    ```python
    query = "SELECT * FROM users WHERE username = '" + username + "';"
    cursor.execute(query)
    ```

  - ✅ **Good - Python**
    ```python
    query = "SELECT * FROM users WHERE username = %s;"
    cursor.execute(query, (username,))
    ```

  - ❌ **Bad - TypeScript (Node.js with mysql2)**
    ```ts
    const userInput = req.body.username;
    const query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    connection.query(query, function (err, results) {
      // ...
    });
    ```

  - ✅ **Good - TypeScript (Node.js with mysql2 using placeholders)**
    ```ts
    const userInput = req.body.username;
    const query = "SELECT * FROM users WHERE username = ?";
    connection.query(query, [userInput], function (err, results) {
      // ...
    });
    ```

- **Functions/APIs involved**:
  - Python: `execute()`, `executemany()` from psycopg2, sqlite3, MySQLdb
  - TypeScript: `connection.query()`, `pool.query()`, raw query methods in Prisma/TypeORM

- **Where to look**:
  - Login/auth flows
  - Search endpoints
  - Data filtering/sorting features
  - Admin panels or internal tools

---

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**:
  - Always validate types, lengths, allowed characters
  - Reject dangerous input, don’t just escape it

- **Encoding/escaping**:
  - Avoid manual escaping — use parameterized queries or prepared statements

- **Framework-specific protections**:
  - Django ORM (Python) uses parameterized queries by default
  - SQLAlchemy, Prisma, and TypeORM reduce SQLi risk via safe query builders

- **Secure configurations**:
  - Use least-privileged DB accounts (e.g., read-only for reading services)
  - Disable verbose error messages in production

- **Defense-in-depth**:
  - Web Application Firewall (WAF)
  - Regular static/dynamic scanning
  - Automated CI/CD checks (e.g., sqlmap, Snyk, GitHub CodeQL)

---

## 🔐 Blockchain Context (if applicable)

- While smart contracts don’t use SQL, **off-chain components in Web3 apps** often do.
- Example: A dApp's backend API that queries metadata from a SQL DB for NFTs or users.
- If the backend builds queries insecurely, it can be SQL injectable — just like in Web2.
- **Web3-specific risk**: Combining SQLi with wallet phishing, social engineering, or malicious signing flows.

---
