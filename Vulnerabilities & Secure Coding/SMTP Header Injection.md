## 🧠 Description

- **What it is (in simple terms + technical explanation)**
    
    - **Simple Terms:** SMTP Header Injection is like a malicious user adding extra lines (or even entirely new sections) to an email's "envelope" (the headers) when they're only supposed to fill in a specific field, like the "To" address or the "Subject." This lets them change who the email is really from, send it to secret recipients, or even alter the entire email's content.
        
    - **Technical Explanation:** SMTP (Simple Mail Transfer Protocol) Header Injection, often referred to as Email Header Injection or CRLF Injection in email contexts, occurs when an application constructs an email using untrusted user input without properly sanitizing or validating it for line break characters (CRLF: Carriage Return `\r` and Line Feed `\n`). An attacker injects these CRLF sequences, followed by arbitrary header fields (e.g., `Bcc:`, `From:`, `Subject:`), into an input field that is later used to construct an email header. This allows the attacker to forge email headers, send spam, launch phishing attacks, or potentially even inject content into the email body.
        
- **Where it occurs (context: frontend, backend, API, blockchain, etc.)**
    
    - **Backend:** Primarily occurs in the **backend application** responsible for generating and sending emails. This includes:
        
        - Contact forms.
            
        - Password reset functionalities.
            
        - Email notification services.
            
        - User feedback forms.
            
        - Any feature where user input directly influences email construction (recipients, subject, body content).
            
    - **API:** Common in APIs that trigger email sending, where input parameters for email fields are passed directly to an email client/library.
        
- **Root cause (e.g. untrusted input, broken auth, etc.)**
    
    - **Untrusted Input:** The fundamental root cause. The application fails to sanitize or properly encode user-supplied data (e.g., email address, subject line, message body) before embedding it into the SMTP headers.
        
    - **Improper CRLF Handling:** The email sending library or custom code does not strip out or escape `\r` (CR) and `\n` (LF) characters from user input that is intended for single-line header fields. SMTP protocols use CRLF to signify the end of a header line.
        
    - **Lack of Contextual Encoding:** The application doesn't understand the context (email header vs. email body) when injecting user input.
        
- **The different types (if applicable)**
    
    - **Header Forgery:** Injecting new header fields (e.g., `From:`, `Bcc:`, `Cc:`, `Reply-To:`).
        
    - **Recipient Injection:** Adding new `To:`, `Cc:`, or `Bcc:` recipients. This can be used for spamming or phishing.
        
    - **Subject/Body Injection:** Manipulating the subject or injecting arbitrary content into the email body by double CRLF (`\r\n\r\n`) to break out of headers and start new content.
        
    - **Email Spoofing:** Changing the apparent sender of the email.
        

## 🧪 Exploitation Techniques

- **Step-by-step walkthrough of how it’s exploited**
    
    1. **Identify Email Sending Functionality:** Find a web form or API endpoint that sends an email where at least one user-controlled field is incorporated into the email headers or body (e.g., a "Contact Us" form where the user's email is used as the `Reply-To` or `From` header).
        
    2. **Test for CRLF Injection:**
        
        - In the vulnerable input field, inject a basic CRLF sequence followed by a test header: `user@example.com%0D%0AUnrelated-Header: Test`. (`%0D%0A` is URL-encoded CRLF).
            
        - Submit the form.
            
        - Check the received email (or email logs if available) to see if `Unrelated-Header: Test` appeared in the email headers.
            
    3. **Craft Malicious Payload:** Once CRLF injection is confirmed, craft a more malicious payload.
        
        - **Recipient Injection (Spam/Phishing):** Inject `Bcc:` or `Cc:` to send email to arbitrary recipients.
            
            - _Input:_ `legit@example.com%0D%0ABcc: spam_target@evil.com`
                
        - **Sender Forgery (Spoofing):** Change the `From:` header to make the email appear to come from someone else.
            
            - _Input:_ `legit@example.com%0D%0AFrom: spoofed@company.com`
                
        - **Content/Subject Injection:** Inject a new subject or entire body content. This requires `\r\n\r\n` to signify the end of headers.
            
            - _Input:_ `legit@example.com%0D%0ASubject: Your password has expired!%0D%0A%0D%0AClick here to reset: http://phishing.com/reset`
                
    4. **Deliver Payload:** Submit the malicious input through the application.
        
    5. **Verify Impact:** Check the recipient's inbox or mail server logs to confirm that the malicious headers or content were successfully injected.
        
- **Payload examples (URL-encoded)**
    
    - **Injecting BCC Header:** `test@example.com%0D%0ABcc: attacker@evil.com`
        
    - **Injecting FROM Header (Email Spoofing):** `no-reply@example.com%0D%0AFrom: admin@company.com`
        
    - **Injecting Subject and Body (Email Splitting):** `victim@example.com%0D%0ASubject: Urgent: Account Suspension Notice%0D%0A%0D%0ADear customer,%0D%0AYour account will be suspended unless you verify your details at: http://malicious.link`
        
    - **Injecting `Return-Path` or other headers:** `user@example.com%0D%0AReturn-Path: <attacker@evil.com>`
        
- **Tools used**
    
    - **Web Browser Developer Tools:** For inspecting network requests and directly modifying form inputs.
        
    - **Burp Suite (or OWASP ZAP):** Essential for intercepting and modifying HTTP requests to inject CRLF sequences (e.g., using Repeater, or Intruder for fuzzing common fields).
        
    - **`curl` / Postman / Insomnia:** For crafting and sending raw HTTP requests with specific payloads to test API endpoints.
        
    - **Mail Client/Server Access:** To check the headers and content of received emails for successful injection.
        
- **Real-world examples (CVE, bugs in libraries or apps)**
    
    - **CVE-2017-1000499 (Swiftmailer library):** A popular PHP email library had a CRLF injection vulnerability that could be exploited to inject arbitrary SMTP headers.
        
    - **Many "Contact Us" forms:** Historically, many custom web application contact forms have been vulnerable due to direct concatenation of user input into email parameters.
        
    - **Various web frameworks/libraries:** While major frameworks have protections, custom email sending utilities or older versions of specific libraries have been found vulnerable.
        

## 🔎 Code Review Tips

- **What patterns or red flags to look for**
    
    - **Direct String Concatenation:** Any code that directly concatenates user input into strings that will be used as email headers or parts of the SMTP command.
        
    - **Lack of CRLF Filtering:** Absence of explicit code to remove `\r` and `\n` characters from user-supplied values before they are used in email headers.
        
    - **`eval()` or `exec()` on Email Components:** While less common, dynamic construction of email commands (e.g., using `system()` to call an external mail client) can open up command injection if input is not validated for CRLF.
        
    - **Custom Email Sending Functions:** Instead of using well-vetted libraries, custom code for email construction is a red flag.
        
- **Bad vs good code examples (especially Python and TS)**
    
    - **Bad Python (Subject Line Injection):**
        
        ```python
        # BAD: User input directly used in subject header
        import smtplib
        from email.mime.text import MIMEText
        
        def send_email_bad(to_addr, user_subject, message_body):
            msg = MIMEText(message_body)
            msg['Subject'] = user_subject # VULNERABLE HERE
            msg['From'] = 'noreply@example.com'
            msg['To'] = to_addr
        
            # This part would typically be handled by an SMTP server connection
            # s = smtplib.SMTP('localhost')
            # s.send_message(msg)
            # s.quit()
            print(msg.as_string()) # Print for demonstration
        
        # Attacker input from a web form
        attacker_subject = "Normal Subject\r\nBcc: evil@attacker.com\r\nFrom: spoofed@example.com"
        send_email_bad("victim@example.com", attacker_subject, "This is the email body.")
        ```
        
    - **Good Python (Subject Line Mitigation):**
        
        ```python
        # GOOD: Use standard email libraries that handle CRLF internally or explicitly filter
        import smtplib
        from email.mime.text import MIMEText
        
        def send_email_good(to_addr, user_subject, message_body):
            msg = MIMEText(message_body)
        
            # GOOD: Email libraries like email.mime.text typically handle CRLF filtering
            # when assigning to headers, preventing injection.
            # However, explicitly stripping CRLF is an additional safety measure.
            sanitized_subject = user_subject.replace('\r', '').replace('\n', '')
            msg['Subject'] = sanitized_subject # Safer here
        
            msg['From'] = 'noreply@example.com'
            msg['To'] = to_addr
        
            # ... send email
            print(msg.as_string()) # Print for demonstration
        
        safe_subject = "Normal Subject"
        send_email_good("victim@example.com", safe_subject, "This is the email body.")
        
        attacker_subject_attempt = "Normal Subject\r\nBcc: evil@attacker.com"
        # When run, the output will typically show the CRLF characters escaped or removed,
        # preventing them from being interpreted as new headers.
        send_email_good("victim@example.com", attacker_subject_attempt, "This is the email body.")
        ```
        
    - **Bad TypeScript/Node.js (Using `+` for header concatenation with no validation):**
        
        ```ts
        // BAD: Using user input directly in NodeMail's options
        const nodemailer = require('nodemailer');
        const express = require('express');
        const app = express();
        app.use(express.json());
        
        const transporter = nodemailer.createTransport({ /* ... SMTP config ... */ });
        
        app.post('/send-feedback', (req, res) => {
            const userEmail = req.body.email; // Attacker controls this
            const userSubject = req.body.subject; // Attacker controls this
            const userMessage = req.body.message;
        
            const mailOptions = {
                from: 'feedback@example.com',
                to: 'support@example.com',
                // BAD: Directly inserting user input without filtering CRLF
                replyTo: userEmail, // VULNERABLE HERE (especially if attacker injects CRLF)
                subject: userSubject, // VULNERABLE HERE
                text: userMessage
            };
        
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Error sending email.');
                } else {
                    res.send('Feedback sent!');
                }
            });
        });
        ```
        
    - **Good TypeScript/Node.js (Filtering CRLF for Headers):**
        
        ```ts
        // GOOD: Explicitly filter CRLF for header values
        const nodemailer = require('nodemailer');
        const express = require('express');
        const app = express();
        app.use(express.json());
        
        const transporter = nodemailer.createTransport({ /* ... SMTP config ... */ });
        
        // Helper function to sanitize header input
        function sanitizeHeader(input: string): string {
            // Remove all CR and LF characters
            return input ? input.replace(/[\r\n]/g, '') : '';
        }
        
        app.post('/send-feedback', (req, res) => {
            const userEmail = sanitizeHeader(req.body.email); // Apply sanitizeHeader
            const userSubject = sanitizeHeader(req.body.subject); // Apply sanitizeHeader
            const userMessage = req.body.message; // Body often handled differently by email libraries
        
            const mailOptions = {
                from: 'feedback@example.com',
                to: 'support@example.com',
                replyTo: userEmail, // SAFER
                subject: userSubject, // SAFER
                text: userMessage
            };
        
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Error sending email.');
                } else {
                    res.send('Feedback sent!');
                }
            });
        });
        ```
        
- **What functions/APIs are often involved**
    
    - **Email Sending Libraries:**
        
        - Java: `javax.mail.*`, `org.apache.commons.mail.Email`
            
        - Python: `smtplib`, `email.mime.text.MIMEText`, `email.header.Header`
            
        - Node.js: `nodemailer`, `mailgun-js`, `sendgrid/mail`
            
        - PHP: `mail()`, `Swiftmailer`, `PHPMailer`
            
    - **String Manipulation:** Functions like `replace()`, `concat()`, `sprintf()`, `format()` where user input is involved.
        
    - **HTTP Request Body/Query Params:** How values are extracted (`req.body`, `req.query`, `$_POST`, `$_GET`).
        
- **Where in the app codebase you'd usually find this**
    
    - **`mailers` / `email` modules/services:** Dedicated files or classes responsible for email composition and sending.
        
    - **Contact forms / Feedback forms:** Backend handlers for these forms.
        
    - **User registration / Password reset flows:** Code that sends confirmation or reset emails.
        
    - **Notification services:** Any part of the application that generates transactional emails based on user actions.
        
    - **API endpoints:** Where email-related data is accepted as input.
        

## 🛡️ Mitigation Strategies

- **Input validation/sanitization**
    
    - **Primary Mitigation: CRLF Filtering/Stripping:** For _all_ user-supplied input intended for email headers (e.g., `From`, `Subject`, `To`, `Reply-To`), explicitly remove or filter out Carriage Return (`\r` or `%0D`) and Line Feed (`\n` or `%0A`) characters. This is the most effective defense.
        
        - _Example:_ In most languages, a simple `input_string.replace('\r', '').replace('\n', '')` before using it in a header is a strong preventative measure.
            
    - **Whitelist Validation:** For email addresses, use strict regular expressions to ensure the input conforms to a valid email format _before_ using it in `To`, `From`, `Cc`, `Bcc` headers.
        
    - **Length Limits:** Limit the length of header fields to prevent very long strings that might overflow buffers or evade some filters.
        
- **Encoding/escaping best practices**
    
    - While CRLF stripping is paramount, some email libraries might offer specific header encoding functions. Use these where available, but rely on CRLF stripping first.
        
- **Framework-specific protections (e.g., React auto-escapes HTML)**
    
    - **Use Secure Email Libraries:** Favor well-maintained and security-conscious email sending libraries (e.g., NodeMailer, PHPMailer, JavaMail) that are designed to mitigate header injection by sanitizing headers internally or providing methods that prevent CRLF injection. Do not try to build custom SMTP client logic from scratch.
        
    - **Framework-provided Sanitization:** Some web frameworks might offer specific helpers for email-related input.
        
- **Secure configurations (headers, CSPs, etc.)**
    
    - **Mail Server Hardening:** Configure the underlying SMTP server to reject messages with malformed headers or an excessive number of recipients from an application's authenticated user.
        
    - **Least Privilege for Mail User:** If the application authenticates to the SMTP server, ensure it uses credentials with the least privileges necessary (e.g., cannot send arbitrary emails as other users).
        
    - **SPF/DKIM/DMARC:** While not directly preventing injection, implementing these email authentication protocols helps recipients identify and reject spoofed or fraudulent emails, reducing the impact of successful header injection.
        
- **Defense-in-depth**
    
    - **Web Application Firewall (WAF):** Configure WAF rules to detect and block common CRLF injection payloads (`%0D%0A`) in common form fields.
        
    - **Comprehensive Logging:** Log all email sending attempts, including the source IP, destination, subject, and any suspicious input content.
        
    - **Anomaly Detection & Alerting:** Set up alerts for:
        
        - Unusually high volumes of emails sent.
            
        - Emails sent to suspicious external domains.
            
        - Errors from the email sending component indicating malformed headers.
            
        - Attempts to inject CRLF sequences into input fields.
            
    - **Secure Software Development Lifecycle (SSDLC):** Incorporate email security into threat modeling (e.g., for password reset flows), conduct security code reviews focused on email composition, and include automated tests to detect CRLF injection.
        

## 🔐 Blockchain Context (if applicable)

- SMTP Header Injection is **not directly applicable to smart contracts or core blockchain logic**. Smart contracts do not send emails or directly interact with SMTP servers.
    
- **However, it can affect centralized Web3 infrastructure components and dApp backends:**
    
    - **dApp Backend for Notifications:** If a dApp offers email notifications (e.g., for NFT sales, transaction confirmations, or new messages) and uses a traditional backend service for this, that backend could be vulnerable.
        
        - _Example:_ A user sets their notification email address for new NFT offers. If this email address field is vulnerable to SMTP Header Injection, an attacker could inject `Bcc:` headers to spam users or `From:` headers to spoof official dApp emails for phishing campaigns (e.g., "Your wallet is suspended!").
            
    - **Crypto Wallet Password Reset/Account Recovery:** If a centralized crypto wallet service offers email-based password resets or account recovery, and the email generation process is vulnerable, attackers could spoof these emails to gain access to accounts or phish users.
        
    - **Exchange Notification Systems:** Centralized crypto exchanges frequently send emails for login alerts, transaction confirmations, or password resets. If their backend notification system is vulnerable, an attacker could spoof official emails.
        
- **Web3-specific risks (e.g., RPC abuse, signing UI attacks)**
    
    - Successful SMTP Header Injection in a Web3 context typically leads to **phishing attacks** (e.g., spoofing an exchange's "deposit address" notification email to steal funds, or a dApp's "account security alert" email to steal seed phrases). It's a stepping stone for social engineering, rather than a direct exploit on the blockchain itself.
        
    - It does not directly lead to RPC abuse or signing UI attacks, but it _enables_ the social engineering required to trick users into performing such actions on legitimate platforms.