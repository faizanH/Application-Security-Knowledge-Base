## 🧠 Description

- **What it is (in simple terms + technical explanation)**
    
    - **Simple Terms:** Cryptographic failures happen when sensitive information (like passwords, credit card numbers, or personal data) isn't properly protected using encryption. It's like putting your valuables in a safe, but using a flimsy lock, a predictable combination, or leaving the key under the doormat. This allows attackers to easily access or tamper with the data.
        
    - **Technical Explanation:** Cryptographic Failures (formerly "Sensitive Data Exposure" in OWASP Top 10) occur when applications fail to properly protect sensitive data, both at rest (stored) and in transit (transmitted). This often stems from incorrect or insufficient use of cryptographic algorithms, weak key management, improper random number generation, or simply not encrypting data that should be. The result is that sensitive data can be exposed in plaintext, easily decrypted, or tampered with by attackers.
        
- **Where it occurs (context: frontend, backend, API, blockchain, etc.)**
    
    - **Backend:** Most common, especially related to:
        
        - **Data at Rest:** Databases, file systems, caches, logs storing sensitive user data (passwords, PII, financial info).
            
        - **Data in Transit:** Communication between application components, APIs, and external services.
            
        - **Key Management:** How encryption keys are generated, stored, and managed.
            
        - **Password Storage:** How user passwords are hashed and stored.
            
    - **Frontend:** Less direct, but can involve:
        
        - Sending sensitive data over unencrypted HTTP.
            
        - Storing sensitive data in insecure browser storage (e.g., localStorage without encryption).
            
    - **API:** APIs often handle sensitive data in transit or interact with backend storage, making them a common point for cryptographic failures.
        
    - **Configuration Files:** Storing sensitive data (e.g., database credentials, API keys) in plaintext.
        
- **Root cause (e.g. untrusted input, broken auth, etc.)**
    
    - **Insufficient Data Protection Needs Assessment:** Not correctly identifying which data is sensitive and requires encryption.
        
    - **Weak/Deprecated Algorithms:** Using outdated, broken, or insecure cryptographic algorithms (e.g., MD5, SHA1 for hashing; DES, RC4 for encryption; old SSL/TLS versions like SSLv3, TLS 1.0/1.1).
        
    - **Improper Key Management:** Hardcoding keys in code, storing keys in plaintext files, weak key generation (low entropy), lack of key rotation, or insecure key storage.
        
    - **No Encryption Used:** Sensitive data transmitted or stored in plaintext.
        
    - **Insecure Random Number Generation:** Using predictable or cryptographically weak random number generators for salts, IVs (Initialization Vectors), or session tokens.
        
    - **Improper Padding/Modes:** Incorrect use of encryption modes (e.g., ECB mode) or padding schemes.
        
    - **Misconfigured SSL/TLS:** Allowing weak cipher suites, self-signed certificates, or not enforcing HTTPS (e.g., missing HSTS).
        
- **The different types (if applicable)**
    
    - **Weak Hashing:** Using fast, unsalted, or broken hashing algorithms for passwords.
        
    - **Plaintext Data:** Storing or transmitting sensitive data without any encryption.
        
    - **Weak Encryption:** Using easily breakable encryption algorithms or modes.
        
    - **Poor Key Management:** Issues with key generation, storage, rotation, and access control.
        
    - **Broken TLS/SSL:** Misconfigurations in TLS/SSL implementation (weak ciphers, outdated protocols, improper certificate validation).
        
    - **Insufficient Entropy:** Predictable random numbers used for cryptographic operations.
        

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough of how it’s exploited**
    
    1. **Identify Sensitive Data:** Determine what sensitive data the application handles (passwords, PII, financial details).
        
    2. **Assess Protection (In Transit):**
        
        - Use a proxy (Burp Suite) or network sniffer (Wireshark) to intercept traffic.
            
        - Check if HTTP is used instead of HTTPS for login or sensitive data submission.
            
        - If HTTPS is used, check for weak TLS versions (SSLv3, TLS 1.0/1.1) or weak cipher suites using tools like `sslyze` or `nmap`'s SSL scripts.
            
        - Attempt to perform an SSL Stripping attack (downgrade HTTPS to HTTP).
            
        - If weak ciphers are found, attempt to decrypt intercepted traffic (though often computationally intensive).
            
    3. **Assess Protection (At Rest):**
        
        - If an application vulnerability (e.g., SQL Injection, Path Traversal, File Upload) allows access to the database or file system, check if sensitive data (e.g., credit card numbers, PII) is stored in plaintext.
            
        - If passwords are hashed, retrieve the password hashes.
            
        - Look for hardcoded encryption keys in source code or easily accessible configuration files.
            
    4. **Exploit Weak Hashing (for Passwords):**
        
        - If unsalted or weak hashes (e.g., MD5, SHA1) are obtained, use rainbow tables or brute-force tools (`Hashcat`, `John the Ripper`) to crack the hashes and recover plaintext passwords.
            
        - If salted but weak/fast hashes, brute-force with a dictionary attack.
            
    5. **Exploit Weak Key Management/Encryption:**
        
        - If an encryption key is found (e.g., hardcoded, in a public config file), use it to decrypt any encrypted data found.
            
        - If a custom/weak encryption algorithm is used, attempt cryptanalysis to break it.
            
    6. **Information Disclosure/Account Takeover:**
        
        - Recovered plaintext data (passwords, PII) can lead to account takeovers, identity theft, or further lateral movement.
            
        - Decrypted communications reveal sensitive information.
            
- **Payload examples (conceptual - exploitation is about decryption/cracking, not injection)**
    
    - **SSL Stripping (using `bettercap` or `sslstrip`):** No direct payload, but a technique to downgrade connections.
        
    - **Password Hash (example of what's** _**found**_**, not injected):**
        
        - `admin:e10adc3949ba59abbe56e057f20f883e` (MD5 of "123456")
            
        - `user:$2a$10$abcdefghijklmnopqrstuu.abcdefghijklmnopqrstuu` (bcrypt hash)
            
    - **Ciphertext (example of what's** _**found**_**):** `U2FsdGVkX1+9f...` (AES ciphertext)
        
- **Tools used**
    
    - **Network Sniffers:** Wireshark, tcpdump.
        
    - **Proxy Tools:** Burp Suite, OWASP ZAP (for intercepting HTTP/S traffic, checking SSL/TLS configurations).
        
    - **SSL/TLS Scanners:** `sslyze`, `testssl.sh`, `nmap` (with `ssl-enum-ciphers` script), Qualys SSL Labs.
        
    - **Password Cracking Tools:** John the Ripper, Hashcat.
        
    - **Cryptanalysis Libraries/Tools:** For attempting to break custom or weak ciphers.
        
    - **File System/Database Access Tools:** Any tool that helps retrieve data at rest (e.g., SQL client, file explorer after gaining initial access).
        
- **Real-world examples (CVE, bugs in libraries or apps)**
    
    - **Heartbleed (CVE-2014-0160):** A critical vulnerability in OpenSSL that allowed attackers to read sensitive data (including private keys and user credentials) from server memory due to a missing bounds check in a TLS heartbeat extension.
        
    - **WannaCry Ransomware (2017):** Exploited EternalBlue (CVE-2017-0144), which itself was a vulnerability in SMB, but the impact often involved unencrypted data being encrypted by ransomware.
        
    - **Equifax Data Breach (2017):** While the initial breach vector was Apache Struts RCE, the subsequent exfiltration of sensitive, unencrypted PII was a major impact of cryptographic failures (or lack thereof).
        
    - **Numerous breaches involving plaintext passwords:** Many incidents where password databases were leaked, and passwords were found to be stored in plaintext or weakly hashed (e.g., MD5, SHA1 without salting/iterations).
        
    - **Downgrade Attacks (e.g., POODLE, FREAK, DROWN):** Exploiting vulnerabilities in TLS/SSL implementations to force clients/servers to use weaker, often export-grade, ciphers that can be broken.
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for**
    
    - **Hardcoded Secrets:** Encryption keys, API keys, database credentials directly in source code.
        
    - **Sensitive Data in Plaintext:** Any code that stores PII, financial data, or authentication tokens in plaintext in databases, logs, or files.
        
    - **Custom Cryptography:** Developers attempting to implement their own encryption algorithms or hashing schemes instead of using well-vetted, standard cryptographic libraries.
        
    - **Weak Hashing Algorithms:** Use of MD5, SHA1, or unsalted/fast hashes for password storage.
        
    - **Predictable Randomness:** Use of `Math.random()` (Java/JS), `rand()` (C/PHP), `random.random()` (Python) for cryptographic purposes (salts, IVs, session IDs).
        
    - **Missing TLS Enforcement:** Absence of HTTP to HTTPS redirects, or lack of HSTS header.
        
    - **Insecure Protocol/Cipher Selection:** Code explicitly allowing old TLS versions or weak cipher suites.
        
    - **Improper IV/Salt Usage:** Reusing IVs, using predictable IVs, or not using salts for password hashing.
        
    - **Logging Sensitive Data:** Logging passwords, credit card numbers, or other PII in plaintext.
        
- **Bad vs good code examples (especially Python and TS)**
    
    - **Bad Python (Weak Password Hashing):**
        
        ```
        # BAD: Using unsalted MD5 for password hashing
        import hashlib
        
        def hash_password_bad(password):
            return hashlib.md5(password.encode()).hexdigest() # VULNERABLE: MD5 is broken, no salt
        
        # Attacker can use rainbow tables or brute-force easily
        hashed_pw = hash_password_bad("mysecretpassword")
        print(f"Bad hash: {hashed_pw}")
        ```
        
    - **Good Python (Strong Password Hashing):**
        
        ```
        # GOOD: Using bcrypt (or Argon2, scrypt) for password hashing with built-in salting and work factor
        import bcrypt
        
        def hash_password_good(password):
            # bcrypt automatically handles salting and iterations (work factor)
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return hashed.decode('utf-8')
        
        def check_password_good(password, hashed_password):
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        
        password = "mysecretpassword"
        hashed_pw_good = hash_password_good(password)
        print(f"Good hash: {hashed_pw_good}")
        print(f"Check password: {check_password_good(password, hashed_pw_good)}")
        ```
        
    - **Bad TypeScript/Node.js (Plaintext Storage/Weak Randomness):**
        
        ```
        // BAD: Storing sensitive data in plaintext or using weak randomness
        const crypto = require('crypto'); // Proper crypto module, but misused
        const express = require('express');
        const app = express();
        
        // BAD: Storing API key directly in code
        const API_KEY = "my_hardcoded_api_key_123";
        
        // BAD: Generating weak session ID
        function generateWeakSessionId(): string {
            return Math.random().toString(36).substring(2, 15); // VULNERABLE: Predictable
        }
        
        // BAD: Sending sensitive data over HTTP
        app.get('/user-data-bad', (req, res) => {
            // Assume this is over HTTP, not HTTPS
            const sensitiveData = { creditCard: '1234-5678-9012-3456' };
            res.send(sensitiveData); // VULNERABLE: Plaintext over HTTP
        });
        ```
        
    - **Good TypeScript/Node.js (Secure Storage/Strong Randomness/HTTPS):**
        
        ```
        // GOOD: Using secure methods for sensitive data and randomness
        const crypto = require('crypto');
        const express = require('express');
        const app = express();
        
        // GOOD: Get API key from environment variables or a secrets manager
        const API_KEY = process.env.API_KEY || 'default_fallback_for_dev';
        
        // GOOD: Generating cryptographically strong session ID
        function generateStrongSessionId(): string {
            return crypto.randomBytes(32).toString('hex'); // SAFER: Cryptographically secure
        }
        
        // GOOD: Ensure all sensitive endpoints use HTTPS
        // (This requires server configuration, e.g., Nginx/Load Balancer for SSL termination)
        // And use HSTS header
        app.use((req, res, next) => {
            if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
                return res.redirect('https://' + req.get('host') + req.url);
            }
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
            next();
        });
        
        app.get('/user-data-good', (req, res) => {
            const sensitiveData = { creditCard: 'ENCRYPTED_DATA_FROM_DB' }; // Data should be encrypted at rest
            res.send(sensitiveData); // Sent over HTTPS
        });
        ```
        
- **What functions/APIs are often involved**
    
    - **Hashing:** `hashlib` (Python), `bcryptjs`, `crypto` (Node.js), `java.security.MessageDigest`, `org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`.
        
    - **Encryption/Decryption:** `crypto` (Node.js), `javax.crypto.*` (Java), `cryptography` (Python).
        
    - **Random Number Generation:** `Math.random()`, `java.util.Random`, `os.urandom()` (Python), `crypto.randomBytes()` (Node.js).
        
    - **TLS/SSL Configuration:** Server configuration files (Apache, Nginx, Tomcat), Node.js `https` module, Java `SSLContext`.
        
    - **Data Storage:** Database ORMs, file I/O functions.
        
    - **Logging:** `console.log`, `logging` libraries.
        
- **Where in the app codebase you'd usually find this**
    
    - **Authentication/User Management Modules:** Password hashing, session ID generation.
        
    - **Data Access Layers (DAO/Repository):** Where data is read from/written to databases or files.
        
    - **API Endpoints:** Where sensitive data is received or sent.
        
    - **Configuration Files:** Storing keys, database connection strings.
        
    - **Utility Classes/Functions:** Custom encryption/hashing routines.
        
    - **Deployment/Server Configuration:** Web server config (Nginx, Apache), load balancer config, cloud security group rules.
        
    - **Logging Configuration:** Where logging levels and content are defined.
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**
    
    - While not directly preventing cryptographic failures, robust input validation helps ensure that data intended for encryption is in the correct format, preventing other vulnerabilities that could expose it.
        
- **Encoding/escaping best practices**
    
    - Not directly applicable to cryptographic failures.
        
- **Framework-specific protections (e.g., React auto-escapes HTML)**
    
    - **Utilize Secure Cryptographic Libraries:** Always use standard, well-vetted, and up-to-date cryptographic libraries and APIs provided by the language or framework (e.g., `bcrypt` or `Argon2` for password hashing, `AES-256 GCM` for encryption). **Never implement custom crypto.**
        
    - **Framework Security Features:** Leverage framework features for secure session management, secure cookie flags (HttpOnly, Secure, SameSite), and built-in password encoders.
        
- **Secure configurations (headers, CSPs, etc.)**
    
    - **Data Classification:** Identify and classify all sensitive data (PII, financial, health, credentials) processed, stored, or transmitted by the application.
        
    - **Encrypt Data at Rest:** Encrypt all sensitive data stored in databases, file systems, backups, and caches using strong, modern encryption algorithms (e.g., AES-256) and proper key management (e.g., KMS, hardware security modules).
        
    - **Encrypt Data in Transit:** Enforce HTTPS/TLS 1.2 or higher for all communication involving sensitive data (client-server, server-to-server, API calls). Use HSTS (HTTP Strict Transport Security) to prevent downgrade attacks.
        
    - **Strong Password Hashing:** Store passwords using strong, adaptive, and salted hashing functions with a sufficient work factor (e.g., Argon2, bcrypt, scrypt, PBKDF2).
        
    - **Secure Key Management:** Implement robust key management practices:
        
        - Generate keys cryptographically randomly.
            
        - Store keys securely (e.g., KMS, hardware security modules, vault solutions).
            
        - Rotate keys regularly.
            
        - Control access to keys using least privilege.
            
    - **Cryptographically Secure Random Number Generators (CSPRNGs):** Use CSPRNGs for all cryptographic operations requiring randomness (salts, IVs, session IDs, token generation).
        
    - **Disable Weak Protocols/Ciphers:** Configure web servers, load balancers, and application servers to disable outdated SSL/TLS protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites.
        
    - **Disable Caching for Sensitive Data:** Prevent caching of responses containing sensitive data.
        
    - **Secure Error Handling:** Do not log or display sensitive data in error messages.
        
- **Defense-in-depth**
    
    - **Network Segmentation:** Isolate sensitive data stores (databases) with network firewalls.
        
    - **Web Application Firewall (WAF):** Can provide a layer of defense against some attacks that might lead to data exposure, but not a primary cryptographic control.
        
    - **Intrusion Detection/Prevention Systems (IDS/IPS):** Monitor for suspicious activity that might indicate data exfiltration.
        
    - **Comprehensive Logging & Monitoring:** Log all access to sensitive data, authentication failures, and cryptographic errors. Alert on suspicious patterns.
        
    - **Regular Security Audits & Pentesting:** Conduct thorough security assessments, including configuration reviews of cryptographic implementations.
        
    - **Security Training:** Train developers on secure cryptographic practices and the importance of data protection.
        

## 🔐 Blockchain Context (if applicable)

- **How this vuln appears in smart contracts or crypto wallet code**
    
    - **Smart Contracts (Solidity):**
        
        - **Weak Randomness:** Smart contracts are deterministic. Using `block.timestamp`, `block.number`, `blockhash`, or `tx.origin` for randomness is highly insecure and predictable, leading to exploitable outcomes in gambling dApps or NFT mints. This is a cryptographic failure in the sense of insecure entropy.
            
        - **Predictable Private Keys (Off-chain):** If a wallet or dApp generates private keys using weak or predictable random number generators, an attacker could guess or brute-force private keys, leading to fund theft.
            
        - **Improper Use of Hashing:** While `keccak256` is strong, using it incorrectly (e.g., hashing concatenated private data without salting or proper padding) can lead to pre-image or length-extension attacks if the context isn't understood.
            
        - **Signature Replay Attacks:** If signatures are not properly tied to a unique transaction hash (nonce, chain ID), an attacker could "replay" a valid signature on a new transaction. This is a cryptographic failure in integrity.
            
    - **Crypto Wallet Code / Blockchain Node Software (Off-chain):**
        
        - **Insecure Private Key Storage:** Private keys stored in plaintext, weakly encrypted, or with hardcoded/predictable encryption keys.
            
        - **Weak Password Hashing:** If wallet software uses weak hashing for user passwords protecting local wallets.
            
        - **Vulnerable TLS/SSL:** If wallet software or blockchain nodes communicate over insecure TLS connections, allowing MITM attacks to steal credentials or manipulate data.
            
        - **Weak Key Derivation:** Using weak KDFs (Key Derivation Functions) for converting passphrases to encryption keys.
            
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks)**
    
    - **Private Key Exfiltration:** The most severe impact. Weak cryptography in wallet software directly leads to private key theft, enabling direct fund transfer.
        
    - **Unauthorized Transaction Signing:** If a wallet's internal encryption is weak, an attacker could decrypt a private key and sign unauthorized transactions.
        
    - **Predictable Outcomes in dApps:** For gambling or NFT minting dApps, predictable "randomness" (a cryptographic failure) allows attackers to guarantee wins or mint rare NFTs, leading to financial loss for other users.
        
    - **Phishing/Spoofing:** Weak TLS on RPC endpoints or dApp frontends could allow MITM attacks, enabling attackers to serve malicious dApp code or trick users into signing malicious transactions (signing UI attack).
        
    - **RPC Abuse:** If an RPC node's authentication relies on weak cryptography or hardcoded keys, an attacker could gain unauthorized access to the node.
        
    - **Bridge/Cross-Chain Vulnerabilities:** Cryptographic failures in cross-chain bridges (e.g., weak signature verification, replay attacks) can lead to large-scale fund theft.