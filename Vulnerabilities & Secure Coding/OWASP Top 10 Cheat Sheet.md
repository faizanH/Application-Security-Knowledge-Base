This cheat sheet provides a concise overview of the OWASP Top 10 Application Security Risks (2021 edition), focusing on what each vulnerability is, how it's exploited, and key mitigation strategies.

## A01:2021 – Broken Access Control

- **What it is:** Flaws in how access to resources (functions, data) is enforced. Users can bypass authorization checks to perform actions or access data they shouldn't.
    
- **How it's exploited:**
    
    - **IDOR (Insecure Direct Object Reference):** Changing a URL parameter or API ID to access another user's data (e.g., `account?id=123` to `account?id=456`).
        
    - **Privilege Escalation:** Gaining higher privileges (e.g., user to admin) by manipulating roles, accessing admin functions directly, or exploiting misconfigurations.
        
    - **Horizontal Privilege Escalation:** Accessing another user's data/functions at the same privilege level.
        
    - **Vertical Privilege Escalation:** Accessing higher-privileged functions/data.
        
- **Key Mitigations:**
    
    - **Deny by Default:** Implement authorization logic to deny all access unless explicitly granted.
        
    - **Server-Side Enforcement:** Implement all access control checks on the trusted server-side code.
        
    - **Least Privilege:** Grant users/roles only the minimum necessary permissions.
        
    - **Unique, Non-Predictable IDs:** Use UUIDs or cryptographically strong random IDs instead of sequential integers for direct object references.
        
    - **Role-Based Access Control (RBAC) / Attribute-Based Access Control (ABAC):** Implement granular authorization models.
        
    - **Session Management:** Securely invalidate sessions on logout, password change.
        

## A02:2021 – Cryptographic Failures

- **What it is:** Sensitive data (passwords, PII, financial info) is not properly protected, either at rest (stored) or in transit (transmitted), due to weak encryption, poor key management, or lack of encryption.
    
- **How it's exploited:**
    
    - **Plaintext Exposure:** Attacker gains access to databases/files and finds sensitive data unencrypted.
        
    - **Weak Hashing:** Cracking weakly hashed passwords (e.g., unsalted MD5, SHA1) using rainbow tables or brute-force.
        
    - **Weak Encryption:** Decrypting data encrypted with outdated or broken algorithms (e.g., DES, RC4) or improper modes (e.g., ECB).
        
    - **Key Management Flaws:** Finding hardcoded encryption keys, predictable keys, or insecure key storage.
        
    - **TLS/SSL Downgrade:** Forcing connections to use weaker, exploitable TLS versions or ciphers.
        
- **Key Mitigations:**
    
    - **Data Classification:** Identify and classify all sensitive data.
        
    - **Encryption at Rest:** Encrypt all sensitive data in databases, file systems, backups (e.g., AES-256 GCM).
        
    - **Encryption in Transit:** Enforce HTTPS/TLS 1.2+ for all sensitive communication. Use HSTS.
        
    - **Strong Password Hashing:** Use adaptive, salted hashing functions (e.g., Argon2, bcrypt, scrypt, PBKDF2).
        
    - **Secure Key Management:** Use KMS (Key Management Systems), hardware security modules (HSMs), or secure vaults for key generation, storage, and rotation.
        
    - **CSPRNGs:** Use cryptographically secure random number generators for all cryptographic purposes (salts, IVs, session IDs).
        
    - **Avoid Custom Crypto:** Never implement your own cryptographic algorithms. Use well-vetted, standard libraries.
        

## A03:2021 – Injection

- **What it is:** Untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing unauthorized data.
    
- **How it's exploited:**
    
    - **SQL Injection (SQLi):** Injecting malicious SQL into input fields to manipulate database queries (e.g., `username=' OR 1=1 --`, `UNION SELECT`).
        
    - **Cross-Site Scripting (XSS):** Injecting malicious client-side scripts (JavaScript) into web pages viewed by other users.
        
        - **Stored XSS:** Payload saved on server (e.g., in a comment) and executed when others view it.
            
        - **Reflected XSS:** Payload echoed immediately in response (e.g., via URL parameter).
            
        - **DOM XSS:** Payload executed by client-side script manipulating the DOM.
            
    - **Command Injection (OS Command Injection):** Injecting OS commands into input fields that are passed to a system shell (e.g., `IP; rm -rf /`).
        
    - **LDAP Injection, NoSQL Injection, XPath Injection:** Similar principles applied to other query languages.
        
- **Key Mitigations:**
    
    - **Parameterized Queries (SQLi):** Use prepared statements with bind variables. Never concatenate user input directly into SQL queries.
        
    - **Contextual Output Encoding (XSS):** Encode all user-generated content based on the HTML context (HTML, attribute, JavaScript, URL).
        
    - **Strict Input Validation:** Whitelist allowed characters, formats, and values for all input.
        
    - **Avoid Shell Execution (Command Injection):** Use safer APIs that execute programs directly with arguments (e.g., `subprocess.run(shell=False)`), not via a shell.
        
    - **HTML Sanitization:** For rich text, use a robust, whitelist-based HTML sanitization library.
        
    - **Content Security Policy (CSP):** As a defense-in-depth for XSS, restrict script sources.
        

## A04:2021 – Insecure Design

- **What it is:** A new category focusing on design flaws. It's about security deficiencies that arise from missing or ineffective control design, rather than implementation bugs. It's a fundamental flaw in the architecture.
    
- **How it's exploited:** Attackers exploit the lack of preventative controls or inherent design weaknesses. This isn't a specific payload, but a category of vulnerabilities resulting from poor design. Examples:
    
    - **Missing Rate Limiting:** Brute-forcing login or password reset.
        
    - **Trusting Client-Side Input:** Relying on frontend validation.
        
    - **Lack of Segmentation:** Flat networks allowing lateral movement.
        
    - **Insecure Business Logic Flows:** Flaws in multi-step processes (e.g., allowing price manipulation in an e-commerce checkout).
        
    - **No Centralized Authorization:** Each developer implements authorization ad-hoc.
        
- **Key Mitigations:**
    
    - **Threat Modeling:** Conduct systematic threat modeling (e.g., STRIDE) early and continuously in the SDLC.
        
    - **Secure Design Principles:** Implement secure defaults, least privilege, defense-in-depth, separation of duties.
        
    - **Architecture Reviews:** Conduct security reviews of application and network architecture.
        
    - **Secure Design Patterns:** Use established secure design patterns (e.g., API gateways, microservices with strong isolation).
        
    - **Rate Limiting:** Implement for authentication, password reset, and other sensitive actions.
        
    - **Trust Boundaries:** Clearly define and enforce trust boundaries between components.
        

## A05:2021 – Security Misconfiguration

- **What it is:** Insecure configurations across any part of the application stack (web servers, databases, frameworks, custom code, cloud services). This includes insecure defaults, unpatched systems, verbose error messages, and unnecessary features.
    
- **How it's exploited:**
    
    - **Default Credentials:** Logging in with default usernames/passwords (e.g., `admin/admin`).
        
    - **Directory Listing:** Browsing web-accessible directories to find sensitive files (config files, backups, source code).
        
    - **Verbose Errors:** Triggering errors to reveal stack traces, database schemas, or internal paths.
        
    - **Unpatched Software:** Exploiting known CVEs in outdated web servers, app servers, OS, or frameworks.
        
    - **Public Cloud Storage:** Accessing publicly exposed S3 buckets or other cloud storage.
        
    - **Exposed Admin Interfaces:** Accessing administrative panels that are not properly secured.
        
- **Key Mitigations:**
    
    - **Hardening Guides:** Follow industry benchmarks (e.g., CIS Benchmarks) for all components.
        
    - **Remove Defaults:** Change all default passwords, disable default accounts.
        
    - **Disable Unnecessary Features:** Turn off all unneeded services, ports, and debugging functionalities in production.
        
    - **Secure Error Handling:** Provide generic error messages to users, log detailed errors internally.
        
    - **Regular Patch Management:** Implement a rigorous, automated process for timely application of security updates.
        
    - **Infrastructure as Code (IaC):** Define and deploy configurations securely and consistently.
        
    - **Automated Configuration Audits:** Use tools to scan configurations against baselines.
        
    - **Network Segmentation:** Limit network access to only necessary ports and IPs.
        

## A06:2021 – Vulnerable and Outdated Components

- **What it is:** Using software components (libraries, frameworks, modules, operating system, web server) that have known security vulnerabilities, are no longer maintained, or are simply out-of-date.
    
- **How it's exploited:**
    
    - **Fingerprinting:** Identifying component versions (e.g., via HTTP headers, error messages, static file names).
        
    - **CVE Lookup:** Searching public vulnerability databases (NVD, Exploit-DB) for known exploits for identified versions.
        
    - **Exploitation:** Using publicly available PoCs or crafting exploits to leverage the component's flaw, often leading to RCE, information disclosure, or authentication bypass.
        
- **Key Mitigations:**
    
    - **Software Composition Analysis (SCA):** Use automated tools (Snyk, Dependabot, OWASP Dependency-Check) to continuously scan for known vulnerabilities in all dependencies (direct and transitive).
        
    - **Maintain SBOM:** Keep an accurate Software Bill of Materials.
        
    - **Regular Patching:** Implement a robust, automated patch management process for all OS, application, and library components.
        
    - **Remove Unused Dependencies:** Reduce attack surface by removing unneeded libraries.
        
    - **Subscribe to Advisories:** Monitor security bulletins for components in use.
        
    - **Security Gating:** Block builds/deployments if critical vulnerabilities are found.
        

## A07:2021 – Identification and Authentication Failures

- **What it is:** Flaws related to user identity, authentication, and session management. Attackers can compromise passwords, session tokens, or exploit weak authentication mechanisms to assume other users' identities.
    
- **How it's exploited:**
    
    - **Brute-Force/Credential Stuffing:** Guessing passwords or using stolen credentials from other breaches.
        
    - **Weak Passwords:** Exploiting easily guessable or common passwords.
        
    - **Session Hijacking:** Stealing session tokens (e.g., via XSS, network sniffing) to impersonate a logged-in user.
        
    - **Session Fixation:** Tricking a user into using a predictable session ID.
        
    - **Missing MFA:** Bypassing authentication if only a single factor is used.
        
    - **Insecure Password Recovery:** Exploiting weak password reset/recovery flows.
        
- **Key Mitigations:**
    
    - **Strong Password Policies:** Enforce complexity, length, and uniqueness.
        
    - **Multi-Factor Authentication (MFA):** Implement MFA for all users, especially privileged ones.
        
    - **Strong Password Hashing:** Use adaptive, salted hashing (Argon2, bcrypt).
        
    - **Rate Limiting:** Implement for login attempts, password resets, and account creation.
        
    - **Secure Session Management:** Use high-entropy session IDs, set HttpOnly, Secure, and SameSite flags for cookies. Invalidate sessions on logout/password change.
        
    - **Account Lockout:** Implement temporary account lockouts after multiple failed login attempts.
        
    - **Identity Verification:** Robust identity verification for password recovery.
        

## A08:2021 – Software and Data Integrity Failures

- **What it is:** A new category focusing on integrity. It's about code and infrastructure that lacks integrity verification. It happens when applications rely on plugins, libraries, or updates from untrusted sources, or fail to verify the integrity of critical data, leading to potential malicious code or data injection.
    
- **How it's exploited:**
    
    - **Supply Chain Attacks:** Injecting malicious code into software updates, libraries, or build processes (e.g., SolarWinds, Log4j).
        
    - **Insecure Deserialization (re-categorized):** Manipulating serialized objects to execute arbitrary code (covered in A02:2021 in previous OWASP, now here).
        
    - **Unverified Updates:** Applications downloading and executing unverified updates or plugins.
        
    - **Critical Data Tampering:** Modifying sensitive data without integrity checks (e.g., checksums, digital signatures).
        
- **Key Mitigations:**
    
    - **Software Supply Chain Security:** Use trusted repositories, verify package integrity (checksums, signatures).
        
    - **Secure Deserialization:** Avoid deserializing untrusted data. If necessary, use serialization filters or cryptographic signatures.
        
    - **File Integrity Monitoring (FIM):** Monitor critical system and application files for unauthorized changes.
        
    - **Code Signing:** Digitally sign code and verify signatures before execution.
        
    - **Immutable Infrastructure:** Deploy new, verified images rather than patching in place.
        
    - **Secure CI/CD Pipelines:** Harden build environments, ensure integrity of build artifacts.
        
    - **Data Integrity Checks:** Implement cryptographic checksums or digital signatures for critical data.
        

## A09:2021 – Security Logging and Monitoring Failures

- **What it is:** Insufficient logging and monitoring, or ineffective incident response, makes it difficult to detect, investigate, and recover from breaches. Without proper visibility, attacks can go unnoticed for extended periods.
    
- **How it's exploited:** Attackers exploit the lack of visibility. They can operate undetected, cover their tracks, and persist in the system without triggering alerts.
    
- **Key Mitigations:**
    
    - **Comprehensive Logging:** Log all security-relevant events (login attempts, access control failures, input validation errors, critical transactions, API calls, system changes).
        
    - **Contextual Logging:** Include sufficient context in logs (user ID, timestamp, source IP, event type, success/failure).
        
    - **Centralized Logging:** Aggregate logs to a centralized SIEM (Security Information and Event Management) system.
        
    - **Real-time Monitoring & Alerting:** Set up alerts for suspicious activities, anomalies, and critical security events.
        
    - **Log Retention:** Store logs securely for sufficient periods for forensic analysis.
        
    - **Incident Response Plan:** Develop, document, and regularly test an incident response plan.
        
    - **Security Operations Center (SOC):** Dedicated team for monitoring and response.
        

## A10:2021 – Server-Side Request Forgery (SSRF)

- **What it is:** A new category. The application fetches a remote resource without validating the user-supplied URL. An attacker can trick the application into making requests to arbitrary internal or external systems, potentially bypassing firewalls.
    
- **How it's exploited:**
    
    - **Internal Network Access:** Making requests to internal IPs (e.g., `192.168.1.1`, `localhost`) to access internal services (databases, admin panels, other APIs).
        
    - **Cloud Metadata Service Access:** Making requests to cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/`) to steal temporary cloud credentials.
        
    - **Port Scanning:** Using the application as a proxy to scan internal ports.
        
    - **Sensitive File Access:** Accessing local files via `file://` scheme (e.g., `file:///etc/passwd`).
        
- **Key Mitigations:**
    
    - **Whitelist URLs:** Strictly whitelist allowed URL schemes, hosts, and ports for remote resource fetching.
        
    - **Disable Unused URL Schemes:** Only allow `http(s)` if needed; disable `file://`, `gopher://`, etc.
        
    - **Normalize URLs:** Ensure URLs are canonicalized before validation.
        
    - **Don't Send Raw Responses:** Avoid sending raw responses from fetched URLs back to the client.
        
    - **Network Segmentation:** Isolate services that perform remote requests from sensitive internal networks.
        
    - **Cloud-Specific Protections:** Enforce IMDSv2 for EC2 instances.