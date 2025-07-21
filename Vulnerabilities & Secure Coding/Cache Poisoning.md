## 🧠 Description

- **What it is (in simple terms + technical explanation)**
    
    - **Simple Terms:** Cache poisoning is like tricking a shared public bulletin board (a cache) into displaying fake or malicious information. Once poisoned, anyone who looks at that part of the bulletin board will see the fake information until it's removed or updated.
        
    - **Technical Explanation:** Cache poisoning is a web application vulnerability where an attacker manipulates a web cache (e.g., CDN, load balancer, reverse proxy, browser cache) into storing and serving malicious content to legitimate users. This occurs when the caching system incorporates unvalidated or attacker-controlled input (typically from HTTP request headers or parts of the URL) into its cache key or directly into the cached response. When a legitimate user requests the same resource, they receive the attacker's poisoned content, which can lead to various attacks like XSS, open redirects, or defacement.
        
- **Where it occurs (context: frontend, backend, API, blockchain, etc.)**
    
    - **Backend/Infrastructure:** Primarily occurs in **web caches** deployed in front of web applications, such as:
        
        - **CDNs (Content Delivery Networks):** Akamai, Cloudflare, AWS CloudFront.
            
        - **Reverse Proxies/Load Balancers:** Nginx, Apache HTTP Server, HAProxy, AWS ELB/ALB.
            
        - **Application-level Caches:** Caching mechanisms within web frameworks or custom application code.
            
    - **Frontend (Browser Cache):** Less impactful for widespread poisoning but can affect individual users if their browser cache is poisoned (e.g., via HTTP response splitting).
        
    - **APIs:** API gateways or caching layers for APIs can also be vulnerable, poisoning API responses.
        
- **Root cause (e.g. untrusted input, broken auth, etc.)**
    
    - **Untrusted Input in Cache Key:** The caching server uses a portion of an HTTP request (often a header like `Host`, `X-Forwarded-Host`, or `User-Agent`) as part of the "cache key" without properly validating or normalizing it. If this part of the key can be controlled by an attacker, they can store malicious content under a seemingly legitimate key.
        
    - **Untrusted Input Reflected in Cached Response:** The application's response includes attacker-controlled input (e.g., from a header, query parameter) that is not properly validated or encoded. If this response is cached, the malicious content becomes static.
        
    - **Inadequate `Vary` Header Configuration:** The `Vary` HTTP header tells the cache which request headers (besides the URL) should be part of the cache key. If the application's response depends on a header that is _not_ included in the `Vary` header, an attacker can manipulate that unkeyed header to poison the cache.
        
    - **Normalization Issues:** Caching systems or applications don't properly normalize URLs or headers (e.g., case sensitivity, redundant encoding), allowing different malicious inputs to resolve to the same cache entry.
        
- **The different types (if applicable)**
    
    - **Unkeyed Input Cache Poisoning:** The most common form. An attacker controls a request component (e.g., a header) that influences the application's response but is _not_ part of the cache key used by the caching server.
        
        - **`Host` header poisoning:** The application generates absolute URLs (e.g., redirects, canonical links) based on the `Host` header. If the proxy doesn't include `Host` in the cache key or canonicalize it, an attacker can send a malicious `Host` header, cause the application to return a malicious redirect, and have the proxy cache it for the legitimate URL.
            
        - **`X-Forwarded-Host` / `X-Forwarded-For` poisoning:** Similar to `Host` header, but targeting specific proxy configurations.
            
        - **`User-Agent`/`Referer` header poisoning:** Less common, but possible if the application's response varies based on these headers and they are not keyed.
            
    - **HTTP Response Splitting/Smuggling:** Can sometimes lead to cache poisoning if an attacker can inject malicious headers (e.g., a new `Content-Length`) that trick an intermediate proxy into caching only part of the response, or splitting one response into two.
        
    - **Web Cache Deception:** A related technique where an attacker tricks a caching server into caching sensitive, user-specific content (e.g., a user's profile page) under a generic, publicly accessible URL, then later retrieves it. This is not strictly "poisoning" but rather abusing cache logic for information disclosure. (This template focuses more on response cache poisoning for widespread impact).
        

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough of how it’s exploited**
    
    1. **Identify Cache Presence:**
        
        - Look for caching headers in responses: `Cache-Control`, `X-Cache`, `Age`, `Expires`, `Vary`.
            
        - Send multiple requests and check if response times decrease (indicating a hit).
            
        - Look for CDN/proxy specific headers.
            
    2. **Identify Unkeyed Input (Header Research):**
        
        - Start with the `Host` header: Send a request to `example.com` with a modified `Host` header (e.g., `Host: attacker.com`). Observe if the application's response (e.g., redirect URL, canonical link, absolute image paths) reflects `attacker.com`.
            
        - Test other common proxy headers: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-Custom-IP-Authorization`.
            
        - Experiment with less common headers that the application might rely on (e.g., `User-Agent` if different cached content is served for different browsers, but `Vary: User-Agent` is missing).
            
    3. **Identify How Unkeyed Input is Reflected:**
        
        - **Redirects:** An application sends a redirect to `http://attacker.com/login` if the `Host` header is manipulated.
            
        - **Links/Scripts:** Absolute URLs for CSS, JS, images, or API endpoints within the HTML point to `attacker.com`.
            
        - **Error Messages:** An application-generated error page might include the malicious `Host` value.
            
        - **XSS Sinks:** If the unkeyed input is reflected unsafely into an HTML context, it can become an XSS payload.
            
    4. **Craft Malicious Request:**
        
        - Construct an HTTP request where the unkeyed header contains the malicious payload (e.g., `Host: evil.com` or `Host: example.com<script>alert(1)</script>`).
            
        - The payload could be:
            
            - An open redirect (e.g., to a phishing site).
                
            - An XSS payload (if reflected unsafely).
                
            - A link to malicious files (e.g., JS, CSS, images).
                
    5. **Poison the Cache:** Send the crafted malicious request to the vulnerable caching server.
        
    6. **Verify Poisoning:** Send a legitimate request (without the malicious header) to the same URL. If the malicious content (e.g., redirect, XSS) is returned, the cache is poisoned.
        
    7. **Force Victim Interaction:** Lure legitimate users to the poisoned URL (e.g., via phishing, drive-by download, or simply waiting for organic traffic).
        
- **Payload examples (categorized)**
    
    - **Redirect Poisoning (via `Host` header):**
        
        - **Request:** `GET / HTTP/1.1\nHost: attacker.com\n\n`
            
        - **Expected Vulnerable App Behavior:** Application generates a redirect like `Location: https://attacker.com/login`.
            
        - **Cached Response:** The legitimate `example.com` URL now serves this malicious redirect to all users.
            
    - **XSS Poisoning (via `Host` header reflection in error page or JS):**
        
        - **Request:** `GET /nonexistent-page HTTP/1.1\nHost: example.com<script>alert(document.domain)</script>\n\n`
            
        - **Expected Vulnerable App Behavior:** An error page is generated that reflects the `Host` header unsafely.
            
        - **Cached Response:** The legitimate error page now contains the XSS payload.
            
    - **Content Injection (via `X-Forwarded-Host`):**
        
        - **Request:** `GET /styles.css HTTP/1.1\nHost: example.com\nX-Forwarded-Host: attacker.com/malicious.css\n\n`
            
        - **Expected Vulnerable App Behavior:** Application generates a `<link>` tag like `<link rel="stylesheet" href="https://attacker.com/malicious.css">`
            
        - **Cached Response:** The legitimate `styles.css` URL now serves HTML with the malicious CSS link.
            
- **Tools used**
    
    - **Burp Suite (or OWASP ZAP):** Essential for intercepting requests, modifying headers, and analyzing responses. Burp's Repeater and Intruder are highly valuable. The "HTTP Request Smuggler" extension can also assist in finding related flaws.
        
    - **`curl`:** For crafting specific HTTP requests from the command line, especially useful for verifying header manipulation.
        
    - **Manual browser testing:** Observing behavior with developer tools.
        
    - **Reconnaissance tools (e.g., `nmap` for service detection):** To understand the underlying network stack that might include caching proxies.
        
- **Real-world examples (CVE, bugs in libraries or apps)**
    
    - **CVE-2015-0201 (Apache HTTP Server):** Vulnerability in `mod_proxy_ajp` could lead to cache poisoning if `ProxyPassReverse` was not used correctly, allowing the `Host` header to be reflected.
        
    - **Various CDN/Reverse Proxy Misconfigurations:** Many real-world examples exist where CDN customers or reverse proxy users fail to properly configure their caching rules or `Vary` headers, leading to vulnerabilities that were often discovered and disclosed through bug bounty programs (e.g., poisoning of static assets, JavaScript files, or redirects).
        
    - **PortSwigger Web Security Academy Labs:** Have excellent, detailed, and realistic examples of various cache poisoning techniques found in real applications.
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for**
    
    - **Generating Absolute URLs:** Any code that constructs full URLs (e.g., for redirects, email links, canonical tags, absolute paths for static assets) using arbitrary request headers like `Host`, `X-Forwarded-Host`, `X-Forwarded-For`.
        
    - **Missing `Vary` Header Logic:** If a response's content depends on a request header (e.g., `Accept-Language`, `User-Agent`, custom headers for A/B testing) but that header is _not_ included in the `Vary` HTTP response header.
        
    - **Unsafe Reflection:** Any reflection of unvalidated user input (especially from headers) directly into HTML or JavaScript without proper encoding.
        
    - **Caching Configurations:** Review caching configurations in web servers (Nginx, Apache), load balancers, CDN settings (e.g., CloudFront behaviors, Cloudflare caching levels) for overly broad caching or insufficient keying.
        
    - **Canonicalization Issues:** Code that doesn't normalize URLs (e.g., case, trailing slashes, redundant encoding) before using them as keys or generating redirects.
        
- **Bad vs good code examples (especially Python and TS)**
    
    - **Bad Python (Host Header Poisoning - Redirect):**
        
        ```python
        # BAD: Using request.headers.get('Host') directly for redirects
        from flask import Flask, redirect, request
        app = Flask(__name__)
        
        @app.route('/')
        def index():
            # Vulnerable if behind a proxy that doesn't fix Host or add X-Forwarded-Host properly
            # And if caching layer doesn't include Host in cache key
            return redirect(f"https://{request.headers.get('Host')}/login")
        ```
        
    - **Good Python (Host Header Poisoning - Redirect):**
        
        ```python
        # GOOD: Using a trusted configured hostname or validating the Host header
        from flask import Flask, redirect, request
        import os
        
        app = Flask(__name__)
        # Get trusted hostname from environment variable, or configure trusted proxies
        TRUSTED_HOSTNAME = os.getenv('TRUSTED_HOSTNAME', 'your-app-domain.com')
        
        @app.route('/')
        def index():
            # If using a proxy, configure it to set X-Forwarded-Host securely
            # Or use a strict whitelist for the Host header
            if request.headers.get('Host') != TRUSTED_HOSTNAME:
                # Log suspicious activity or reject
                # For redirects, generate based on known trusted domain
                return redirect(f"https://{TRUSTED_HOSTNAME}/login")
            return redirect(f"https://{TRUSTED_HOSTNAME}/login") # Always use trusted domain
        ```
        
    - **Bad TypeScript/Node.js (Missing Vary Header):**
        
        ```ts
        // BAD: Response varies by 'User-Agent' but no Vary header
        app.get('/dynamic-content', (req, res) => {
            const userAgent = req.headers['user-agent'];
            let content = 'Default content.';
            if (userAgent && userAgent.includes('Mobile')) {
                content = 'Mobile optimized content.';
            }
            // Response cached might be for mobile, but served to desktop if no Vary: User-Agent
            res.send(`<html><body>${content}</body></html>`);
            // Missing: res.setHeader('Vary', 'User-Agent');
        });
        ```
        
    - **Good TypeScript/Node.js (Proper Vary Header):**
        
        ```ts
        // GOOD: Response includes Vary header for all influencing headers
        app.get('/dynamic-content', (req, res) => {
            const userAgent = req.headers['user-agent'];
            let content = 'Default content.';
            if (userAgent && userAgent.includes('Mobile')) {
                content = 'Mobile optimized content.';
            }
            res.setHeader('Vary', 'User-Agent'); // Crucial for cache correctness
            res.send(`<html><body>${content}</body></html>`);
        });
        ```
        
- **What functions/APIs are often involved**
    
    - **HTTP Header Access:** `request.headers.get('Host')`, `request.getHeader('X-Forwarded-Host')`.
        
    - **URL Generation:** Functions that construct absolute URLs (e.g., `url_for` in Flask, `response.redirect()`, `HttpServletResponse.sendRedirect()`).
        
    - **Caching Middleware/Annotations:** Framework-specific caching annotations (`@Cacheable` in Spring, decorator in Python), or caching middleware configurations.
        
    - **Response Headers Setting:** `response.setHeader('Vary', '...')`, `Cache-Control` header settings.
        
    - **Template Engines:** If they generate URLs or include reflected input.
        
- **Where in the app codebase you'd usually find this**
    
    - **Routing and Controller Logic:** Where requests are handled and responses are generated.
        
    - **Middleware:** Custom middleware that processes headers or responses.
        
    - **Configuration Files:** Web server (Nginx.conf, httpd.conf), Load Balancer, CDN configuration files (e.g., CloudFront distributions, Cloudflare page rules).
        
    - **URL Helper Utilities:** Classes or functions responsible for building URLs.
        
    - **Templating files (Jinja2, Thymeleaf, EJS):** If they dangerously render user-controlled input directly into URL attributes or HTML contexts.
        
    - **Application Cache Configuration:** Where application-level caching strategies are defined.
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**
    
    - **Normalize and Validate Host Header:** Ensure that the `Host` header (and `X-Forwarded-Host` if used) is strictly validated against a whitelist of allowed hostnames for the application. If it doesn't match, reject the request or redirect to the correct canonical domain.
        
    - **Canonicalize URLs/Headers:** Ensure caching systems and applications consistently treat variations of a URL/header (e.g., case, trailing slashes, encoding) as the same resource to prevent cache collisions.
        
- **Encoding/escaping best practices**
    
    - **Contextual Output Encoding:** If any user-controlled input (even from headers) is reflected into HTML, CSS, or JavaScript, always apply proper contextual output encoding to neutralize any malicious payloads (e.g., preventing XSS). This is a defense-in-depth against poisoning with XSS payloads.
        
- **Framework-specific protections**
    
    - Many modern web frameworks (e.g., Spring, Django) have built-in protections or best practices for handling the `Host` header securely and generating URLs correctly. Rely on these framework features.
        
    - Use framework-provided URL generation utilities that are designed to avoid `Host` header poisoning.
        
- **Secure configurations (headers, CSPs, etc.)**
    
    - **Proper `Vary` Header Usage:** Configure the application to send a `Vary` header that lists _all_ HTTP request headers that legitimately cause the response to differ. This ensures the cache forms a unique key based on these headers, preventing poisoning from unkeyed input.
        
    - **Canonical `Host` Header Enforcement:** Configure proxies/CDNs to normalize the `Host` header or strictly only forward a trusted `Host` header to the backend.
        
    - **Strict Caching Policies:**
        
        - **Disable caching for sensitive/dynamic content:** For pages that contain user-specific data, authentication details, or frequently changing information, use `Cache-Control: no-cache, no-store, must-revalidate` and `Pragma: no-cache` in the response.
            
        - **Private Caching:** Use `Cache-Control: private` for user-specific cached content.
            
        - **Short Cache Lifetimes:** Use `max-age` or `s-maxage` with short durations for dynamic content.
            
    - **Web Server/Proxy Hardening:** Configure Nginx, Apache, or other proxies to strictly validate incoming request headers before processing.
        
- **Defense-in-depth**
    
    - **Web Application Firewall (WAF):** A WAF can be configured to block requests containing malicious `Host` or other headers known to be associated with cache poisoning attacks.
        
    - **CDN Configuration:** Carefully review and configure CDN caching behaviors, ensuring that sensitive paths are not cached, or that the cache key includes all necessary parameters.
        
    - **Security Monitoring:** Monitor logs for suspicious access patterns, unexpected redirects, or anomalies related to caching headers.
        
    - **Regular Security Audits:** Conduct regular penetration tests that include testing for cache poisoning vulnerabilities.
        

## 🔐 Blockchain Context (if applicable)

- Cache poisoning is **not directly applicable to smart contracts**. Smart contracts operate deterministically on a blockchain, executing code that is part of the decentralized ledger, without external caching mechanisms in the traditional HTTP sense.
    
- **However, it can affect centralized Web3 infrastructure components:**
    
    - **Blockchain Explorers:** If a blockchain explorer (e.g., Etherscan, Polygonscan) uses a caching layer for displaying transaction data or block information, and this layer is vulnerable to cache poisoning, an attacker could potentially display misleading or malicious transaction details to users, leading to phishing or social engineering.
        
    - **API Gateways for dApps:** If a dApp relies on a centralized API gateway (e.g., for off-chain data, token prices, or NFT metadata) and this gateway's caching mechanism is vulnerable, malicious data could be served to dApp users.
        
    - **Node Providers:** Services that provide RPC access to blockchain nodes (like Infura, Alchemy) might use caching layers. If misconfigured, an attacker could poison cached responses, potentially leading to incorrect data being returned to dApps or wallets. This could influence client-side decisions or display.
        
    - **Frontend dApp Caching:** If a dApp's static frontend files (HTML, JS, CSS) are served from a CDN vulnerable to cache poisoning, an attacker could inject malicious JavaScript that then attempts to steal wallet private keys or trick users into signing malicious transactions (similar to XSS via cache poisoning). This falls under the general Web3 risk of **signing UI attacks** or **malicious frontend injection**.
        
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks)**
    
    - **Signing UI Attacks:** Cache poisoning of a dApp's frontend could serve a malicious JavaScript payload to users. This script could then modify the transaction details displayed in the user's wallet signing prompt, tricking them into signing a different transaction than intended (e.g., sending tokens to an attacker's address instead of a legitimate one).
        
    - **Misleading Data Display:** Poisoning cached responses for token prices, NFT metadata, or historical transaction data could mislead users into making bad financial decisions.
        
    - **Phishing/Defacement:** Direct defacement or redirection to phishing sites for Web3 users.