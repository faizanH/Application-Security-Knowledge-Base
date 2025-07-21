## 1. 💡 Core Concepts & Purpose

- **What is it?** Content Security Policy (CSP) is an HTTP response header that web servers can use to control which resources (e.g., JavaScript, CSS, images, fonts, media) a user agent (browser) is allowed to load for a given page. It's a powerful client-side security mechanism that helps mitigate various types of content injection attacks, primarily Cross-Site Scripting (XSS).
    
- **Key Components/Elements:**
    
    - **`Content-Security-Policy` Header:** The main HTTP response header that defines the policy.
        
    - **Directives:** Keywords that specify allowed sources for different resource types.
        
        - `default-src`: Fallback for any resource type not explicitly listed.
            
        - `script-src`: Specifies valid sources for JavaScript.
            
        - `style-src`: Specifies valid sources for stylesheets.
            
        - `img-src`: Specifies valid sources for images.
            
        - `connect-src`: Applies to XMLHttpRequest (XHR), WebSockets, and EventSource.
            
        - `font-src`: Specifies valid sources for fonts.
            
        - `frame-src`: Specifies valid sources for frames (e.g., `<iframe>`).
            
        - `object-src`: Specifies valid sources for `<object>`, `<embed>`, or `<applet>` tags.
            
        - `base-uri`: Restricts URLs that can be used in a document's `<base>` element.
            
        - `form-action`: Restricts URLs that can be used as the target of form submissions.
            
        - `report-uri` / `report-to`: Specifies a URL where the browser should send JSON reports of CSP violations.
            
    - **Source Values:** Define allowed origins for directives.
        
        - `'self'`: Allows resources from the same origin as the document.
            
        - `'unsafe-inline'`: Allows inline scripts/styles (should be avoided).
            
        - `'unsafe-eval'`: Allows `eval()` and similar methods (should be avoided).
            
        - `data:`: Allows data URIs.
            
        - `https:`, `http:`: Allows resources from any origin using the specified scheme.
            
        - Specific domains: `example.com`, `cdn.example.com`.
            
        - **Nonces (`'nonce-randomvalue'`):** A unique, cryptographically strong random value generated per request, used to whitelist specific inline scripts/styles.
            
        - **Hashes (`'sha256-hashofscript'`):** A hash of the script/style content, used to whitelist specific inline scripts/styles.
            
    - **`Content-Security-Policy-Report-Only` Header:** A "report-only" mode that allows testing a CSP without enforcing it, sending violations to the `report-uri`.
        
- **Why does it exist? What's its primary function?** CSP exists to provide a robust, client-side defense layer against content injection attacks. Its primary function is to restrict the origins from which a browser can load resources, thereby preventing an attacker from injecting and executing malicious scripts (XSS), loading unauthorized images, or submitting forms to phishing sites, even if other server-side sanitization fails. It acts as a "second line of defense" against XSS.
    

## 2. 🔒 Importance for AppSec & Pentesting

- **Why is understanding this critical for security professionals?** CSP is a fundamental client-side security control. For AppSec professionals, understanding CSP is critical for designing secure web applications, especially those handling user-generated content. It provides a powerful mechanism to reduce the impact of XSS vulnerabilities. For pentesters, understanding CSP helps in identifying misconfigurations, bypassing policies, and assessing the true exploitability of XSS flaws.
    
- **How does it underpin application security?**
    
    - **XSS Mitigation:** CSP is the most effective client-side mitigation for XSS. Even if an attacker manages to inject a script payload into the DOM (due to a server-side bug), a strong CSP can prevent that script from executing if its source is not whitelisted.
        
    - **Data Exfiltration Prevention:** `connect-src` can prevent injected scripts from making unauthorized requests to external attacker-controlled domains to exfiltrate data.
        
    - **Clickjacking/UI Redressing Prevention:** `frame-ancestors` directive can prevent the page from being embedded in iframes on other domains.
        
    - **Mixed Content Prevention:** By restricting `http:` sources on an `https:` page, CSP helps prevent mixed content warnings and vulnerabilities.
        
    - **Defense-in-Depth:** It provides a crucial layer of defense, ensuring that even if other server-side input validation and output encoding fail, the browser will still enforce the policy.
        
- **What security boundaries/mechanisms does it provide or interact with?**
    
    - **Browser Security Model:** CSP extends the browser's Same-Origin Policy.
        
    - **Input Validation/Output Encoding:** CSP acts as a fallback if these server-side controls fail.
        
    - **HTTP Security Headers:** It's a key HTTP security header, often used in conjunction with HSTS, X-Frame-Options, X-Content-Type-Options.
        
    - **Web Application Firewalls (WAFs):** While WAFs try to block XSS payloads at the network edge, CSP works at the client-side, enforcing the policy regardless of WAF bypasses.
        

## 3. 😈 Common Security Weaknesses & Attack Vectors

- **Common Misconfigurations/Insecure Defaults:**
    
    - **Missing CSP Header:** The most common "misconfiguration" is simply not having a CSP.
        
    - **Overly Permissive Directives:**
        
        - `default-src *` or `script-src *`: Allows loading resources from anywhere, completely defeating the purpose.
            
        - `script-src 'unsafe-inline'`: Allows all inline scripts, making many XSS attacks trivial.
            
        - `script-src 'unsafe-eval'`: Allows `eval()` and similar functions, which can be exploited.
            
        - `script-src http:` / `https:`: Allows scripts from any domain over HTTP/S.
            
    - **Missing Directives:** Not specifying all relevant directives (e.g., only `script-src` but forgetting `object-src` or `form-action`).
        
    - **Incorrect Nonce/Hash Implementation:** Nonces not being truly random per request, or hashes being incorrectly calculated, leading to bypasses.
        
    - **Relaxed `connect-src`:** Allowing connections to `*` or `data:` can enable data exfiltration via XHR or WebSockets.
        
    - **JSONP Endpoints:** If `script-src` allows a domain that hosts a JSONP endpoint, an attacker might be able to use that endpoint to deliver arbitrary JavaScript.
        
- **Vulnerability Types & Exploitation Methodologies:**
    
    - **CSP Bypass:** The goal of an attacker is to find a way to execute arbitrary JavaScript despite the presence of a CSP.
        
        - **'unsafe-inline' / 'unsafe-eval' presence:** If these are present, XSS is often trivial.
            
        - **Open Redirects/Reflected XSS on Whitelisted Domains:** If `script-src` whitelists `trusted.com`, and `trusted.com` has a reflected XSS or open redirect, the attacker might be able to chain these to execute script.
            
        - **JSONP Endpoints on Whitelisted Domains:** If `script-src` whitelists a domain that hosts a JSONP endpoint, an attacker can use that endpoint to inject and execute arbitrary JavaScript.
            
        - **Missing `base-uri`:** If `base-uri` is not set, an attacker might be able to inject a `<base>` tag that changes the base URL for relative paths, potentially bypassing source restrictions.
            
        - **Incorrect Nonce/Hash:** If nonces are predictable or hashes are miscalculated, the attacker can craft valid payloads.
            
        - **`data:` URI Abuse:** If `script-src data:` is allowed, attackers can encode malicious scripts directly in the URL.
            
        - **HTML Injection + CSP Bypass:** If the application is vulnerable to HTML injection, an attacker might inject tags that leverage allowed sources (e.g., `<img src="malicious.svg">` if SVG allows script, and `img-src` is too broad).
            
- **Relevant Attack Tools:**
    
    - **Web Browser Developer Tools:** Essential for inspecting CSP headers (`Response Headers` tab), observing CSP violations in the `Console` tab, and testing payloads.
        
    - **Burp Suite (or OWASP ZAP):** For intercepting requests, modifying responses to test CSPs, and using built-in scanners/extensions to analyze CSPs.
        
    - **CSP Evaluators/Analyzers:** Online tools (e.g., Google's CSP Evaluator, CSP Validator) that analyze a given CSP for common weaknesses.
        
    - **CSP Bypass Payloads:** Publicly available lists of CSP bypass techniques and payloads (e.g., PortSwigger Web Security Academy labs).
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for**
    
    - **Absence of CSP:** No `Content-Security-Policy` header being set.
        
    - **`'unsafe-inline'` or `'unsafe-eval'`:** These keywords in `script-src` or `style-src` are major red flags.
        
    - **Wildcards (`*`):** Any use of `*` in source directives (e.g., `script-src *`).
        
    - **`http:` or `https:` as source:** Allowing any domain over HTTP/S (`script-src https:`).
        
    - **Missing Directives:** A CSP that only defines `script-src` but omits `object-src`, `base-uri`, `form-action`, `frame-src`, `connect-src`.
        
    - **Predictable Nonces:** Nonces that are not cryptographically random per request.
        
    - **Hardcoded Hashes:** Hashes that are hardcoded and not dynamically generated for inline scripts, making them inflexible and potentially insecure if the script changes.
        
    - **Reliance on CSP Alone:** If the application relies solely on CSP for XSS prevention without proper server-side input validation and output encoding.
        
- **Bad vs good code examples (conceptual - CSP is header-based, not inline code)**
    
    - **Bad CSP (Overly Permissive):**
        
        ```shell
        # Nginx config (BAD)
        add_header Content-Security-Policy "default-src *; script-src 'unsafe-inline' 'unsafe-eval' https: http:; object-src *;";
        ```
        
        _Explanation:_ This CSP effectively does nothing to prevent XSS due to the use of `*`, `'unsafe-inline'`, `'unsafe-eval'`, and `http:/https:`.
        
    - **Good CSP (Strict, using nonce):**
        
        ```shell
        # Nginx config (GOOD - requires backend to generate nonce)
        # This is a conceptual example for Nginx. Real implementation involves backend generating nonce.
        # Backend would generate a random nonce for each request.
        # Example for a Node.js Express app:
        const express = require('express');
        const crypto = require('crypto');
        const app = express();
        
        app.use((req, res, next) => {
            res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
            res.setHeader('Content-Security-Policy', `
                default-src 'self';
                script-src 'self' 'nonce-${res.locals.cspNonce}' https://cdn.jsdelivr.net;
                style-src 'self' 'nonce-${res.locals.cspNonce}';
                img-src 'self' data:;
                connect-src 'self' https://api.example.com;
                frame-ancestors 'self';
                form-action 'self';
                object-src 'none';
                base-uri 'self';
                report-uri /csp-report-endpoint;
            `.replace(/\s+/g, ' ').trim()); // Remove extra whitespace
            next();
        });
        
        // In EJS/Thymeleaf/Jinja2 template:
        // <script nonce="<%= cspNonce %>"> /* inline script */ </script>
        // <style nonce="<%= cspNonce %>"> /* inline style */ </style>
        ```
        
        _Explanation:_ This CSP is strict: * `default-src 'self'`: Only allows resources from the same origin by default. * `script-src 'self' 'nonce-...' https://cdn.jsdelivr.net`: Only allows scripts from the same origin, specific inline scripts with a matching nonce, and scripts from `cdn.jsdelivr.net`. * `'nonce-...'`: Crucial for allowing specific inline scripts without `'unsafe-inline'`. The nonce must be unique per request. * `object-src 'none'`: Disables plugins like Flash/Java applets. * `frame-ancestors 'self'`: Prevents clickjacking. * `report-uri`: Sends violation reports for monitoring.
        
- **What functions/APIs are often involved**
    
    - **Web Server Configuration:** Directives in `httpd.conf`, `nginx.conf`, `web.config` for setting response headers.
        
    - **Application Framework Middleware:** Functions/libraries for setting HTTP headers (e.g., `helmet` in Node.js Express, Spring Security's header configuration).
        
    - **Templating Engines:** How nonces are injected into `script` and `style` tags.
        
    - **Cryptographic Randomness:** `crypto.randomBytes()` (Node.js), `SecureRandom` (Java), `os.urandom()` (Python) for generating nonces.
        
    - **Reporting Endpoints:** Backend API endpoints to receive CSP violation reports.
        
- **Where in the app codebase you'd usually find this**
    
    - **Web server configuration files:** (`nginx.conf`, `httpd.conf`, `web.config`).
        
    - **Application startup/bootstrap files:** Where middleware or global filters are configured.
        
    - **Security Configuration Files:** (e.g., `SecurityConfig.java` in Spring Boot).
        
    - **Templating files:** `.ejs`, `.html`, `.jsp`, `.php` (where `nonce` attributes are added).
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**
    
    - CSP is a client-side control. It acts as a **defense-in-depth** layer. The primary mitigation for XSS remains robust **server-side input validation** (e.g., whitelisting allowed HTML tags and attributes for rich text) and **contextual output encoding**. CSP helps if these fail.
        
- **Encoding/escaping best practices**
    
    - CSP complements, but does not replace, proper output encoding. Output encoding prevents the XSS payload from being rendered as executable code in the first place. CSP prevents it from executing if it _does_ get rendered.
        
- **Framework-specific protections (e.g., React auto-escapes HTML)**
    
    - **Leverage Framework Security Headers:** Use security middleware/libraries provided by frameworks (e.g., `helmet` for Node.js Express, Spring Security's header configuration) to easily set CSP and other security headers.
        
    - **Secure Templating Engines:** Use templating engines that auto-escape HTML by default (e.g., EJS, Jinja2, Thymeleaf) and only allow explicit "safe" rendering after sanitization.
        
- **Secure configurations (headers, CSPs, etc.)**
    
    - **Implement a Strong CSP:**
        
        - **Start with `default-src 'self'`:** This is the most restrictive and safest starting point.
            
        - **Avoid `'unsafe-inline'` and `'unsafe-eval'`:** Refactor inline scripts/styles into external files or use nonces/hashes for specific inline blocks. Avoid `eval()` and similar functions.
            
        - **Specify all Directives:** Don't omit directives; explicitly set them to `'none'` or `'self'` if not needed.
            
        - **Use Nonces or Hashes:** For necessary inline scripts/styles, use cryptographically strong, unique-per-request nonces or content hashes.
            
        - **Restrict `object-src` to `'none'`:** Prevents old plugin vulnerabilities.
            
        - **Set `frame-ancestors 'self'`:** Prevents clickjacking.
            
        - **Set `form-action 'self'`:** Prevents forms from submitting to external sites.
            
        - **Set `base-uri 'self'`:** Prevents base tag injection.
            
    - **Use `Content-Security-Policy-Report-Only`:** Deploy the CSP in report-only mode first to identify violations without blocking legitimate functionality. Use a `report-uri` to collect violation reports.
        
    - **HTTP Strict Transport Security (HSTS):** Use HSTS to enforce HTTPS, complementing CSP by preventing protocol downgrade attacks.
        
- **Defense-in-depth**
    
    - **Comprehensive XSS Prevention:** CSP is one layer. Combine it with strong server-side input validation, contextual output encoding, and secure coding practices.
        
    - **Regular Auditing:** Regularly audit the CSP policy for weaknesses and ensure it remains effective as the application evolves.
        
    - **Security Monitoring:** Monitor CSP violation reports for active attacks or misconfigurations.
        
    - **Automated Security Testing:** Use DAST tools to test CSP effectiveness and SAST tools to identify potential XSS vulnerabilities that CSP might protect against.
        

## 🔐 Blockchain Context (if applicable)

- **How this vuln appears in smart contracts or crypto wallet code**
    
    - **Smart Contracts:** CSP headers are **not applicable** to smart contracts. Smart contracts run on the EVM or similar blockchain VMs and do not serve web content or interact with web browsers in this manner.
        
    - **Web3 Frontend (dApps):** This is highly applicable. Most dApps have a frontend (HTML, CSS, JavaScript) that interacts with the blockchain. If this frontend is hosted on a web server, CSP headers are crucial.
        
        - **Malicious Frontend Injection:** If a dApp's frontend is vulnerable to XSS (e.g., via user-generated content, or a compromised CDN), a strong CSP can prevent the injected malicious script from executing. This is critical for preventing **signing UI attacks**.
            
        - **Compromised Dependencies:** If a JavaScript library used by the dApp frontend is compromised (supply chain attack), a strict CSP can prevent the malicious code within that library from making unauthorized network requests or executing dangerous inline scripts.
            
    - **Crypto Wallet Browser Extensions/Web Wallets:** These are essentially web applications. A strong CSP is vital for their security to prevent malicious websites or injected code from interacting with the wallet's internal logic or exfiltrating sensitive data (e.g., private keys, seed phrases).
        
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks)**
    
    - **Signing UI Attacks:** This is the most direct and critical tie-in. If a dApp frontend is compromised via XSS, an attacker could inject JavaScript to modify the transaction details shown to the user _before_ they sign it with their wallet. A strong CSP (`script-src 'self' 'nonce-...'`, `connect-src 'self'`) can prevent such injected scripts from running, thus protecting the user from signing a malicious transaction.
        
    - **Private Key Exfiltration (via XSS):** A CSP can prevent injected scripts from making outbound network requests to an attacker's server (`connect-src`) to exfiltrate sensitive data like private keys or seed phrases (if they were ever exposed client-side, which they ideally shouldn't be).
        
    - **RPC Abuse (Client-Side):** While RPC abuse often involves server-side compromise, a client-side XSS (prevented by CSP) could theoretically allow an attacker to inject scripts that make unauthorized RPC calls from the user's browser, potentially draining funds or interacting with contracts maliciously.
        
    - **Phishing/Defacement:** CSP helps prevent the dApp frontend from being defaced or redirected to phishing sites via XSS.