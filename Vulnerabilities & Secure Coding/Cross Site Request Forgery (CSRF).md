## 🧠 Description

**What it is:**

- **Simple terms:** Imagine you're logged into your online bank. A malicious website could trick your browser into sending a request to your bank that transfers money, all without your knowledge or consent, because your browser automatically sends your login cookies with the request.
- **Technical explanation:** Cross-Site Request Forgery (CSRF), sometimes pronounced "sea-surf," is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated. CSRF attacks specifically target state-changing requests, not data theft, since the attacker has no way to see the response to the forged request. It exploits the trust that a web application places in a user's browser. When a user is authenticated to a site, their browser stores session cookies. If the user then visits a malicious site, that site can craft a request (e.g., an image tag, a form submission, an AJAX request) to the vulnerable site. The browser, acting on behalf of the user, automatically includes the session cookies with the request, making it appear to the vulnerable site as a legitimate request from the authenticated user.
    

**Where it occurs:**

- **Frontend & Backend:** CSRF is fundamentally a frontend attack (the user's browser is tricked into sending the request) but its success relies on the backend's lack of proper validation to distinguish legitimate requests from forged ones. It primarily impacts web applications.
- **API:** APIs are also susceptible if they rely solely on cookie-based authentication and don't implement CSRF tokens or other protective measures.

**Root cause:**

- **Lack of trust in the client:** The primary root cause is the web application's implicit trust in requests coming from the user's browser, without sufficiently verifying that the user genuinely intended to make that request. Specifically, it's a failure to check the origin of a request.
- **Reliance on session cookies:** Websites that use session cookies for authentication, and don't require further proof of user intent for state-changing operations, are vulnerable.

**The different types:**

- **GET-based CSRF:** The malicious request is embedded within a GET request, often within an `<img>` tag's `src` attribute or an `<a>` tag's `href`. This is limited to actions that can be performed via GET requests.
- **POST-based CSRF:** The malicious request is embedded within a form that is automatically submitted (e.g., via JavaScript) when the user visits the malicious page. This is more common and powerful as most state-changing operations use POST requests.

---

## 🧪 Exploitation Techniques

**Step-by-step walkthrough of how it’s exploited:**

1. **Identify a vulnerable action:** The attacker finds a state-changing action on the target website that doesn't require a CSRF token (e.g., changing email, password, transferring funds, making a purchase).
2. **Capture the legitimate request:** The attacker, acting as a legitimate user, performs the vulnerable action and captures the HTTP request using a proxy tool (like Burp Suite).
3. **Craft a malicious page:** The attacker creates a malicious webpage (e.g., `malicious.html`) containing an HTML form or JavaScript that sends an identical request to the vulnerable application, but with parameters controlled by the attacker.
    - For a POST request, this would typically be a hidden form that auto-submits.
    - For a GET request, it could be an `<img>` tag with the `src` pointing to the malicious URL.
4. **Lure the victim:** The attacker then tricks the victim into visiting the malicious webpage while they are logged into the legitimate application. This can be done via phishing emails, malicious ads, or compromised websites.
5. **Execution:** When the victim visits the malicious page, their browser automatically submits the crafted request to the vulnerable application. Since the victim is logged in, their session cookies are included, and the application processes the request as if it were legitimate, performing the unwanted action.

**Payload examples (categorized):**

- **POST-based CSRF (Hidden Form Auto-Submission):**
    
    HTML
    
    ```html
    <html>
    <body>
      <form id="csrfForm" action="https://bank.example.com/transfer" method="POST">
        <input type="hidden" name="recipient" value="attacker_account" />
        <input type="hidden" name="amount" value="1000" />
        <input type="hidden" name="currency" value="USD" />
      </form>
      <script>
        document.getElementById('csrfForm').submit();
      </script>
      <p>You've won a free iPhone! Click anywhere to claim it.</p>
    </body>
    </html>
    ```
    
- **GET-based CSRF (Image Tag):**
    
    HTML
    
    ```html
    <html>
    <body>
      <img src="https://example.com/user/delete?id=victim_account" style="display:none;">
      <p>Welcome to my amazing website!</p>
    </body>
    </html>
    ```
    

**Tools used:**

- **Burp Suite:** Essential for capturing, modifying, and replaying requests to identify vulnerable actions and craft payloads.
- **Web browser developer tools:** Useful for inspecting network requests and understanding how a legitimate application interacts with its backend.
- **Basic text editor:** For crafting the malicious HTML/JavaScript files.
- **Web server:** To host the malicious HTML file (e.g., Python's `http.server` module).

**Real-world examples (CVE, bugs in libraries or apps):**

- Many legacy web applications have been vulnerable to CSRF. While modern frameworks often provide built-in protections, misconfigurations or custom code can still introduce vulnerabilities.
- **CVE-2017-9804 (Apache Struts):** While primarily known for remote code execution, older versions of Struts had CSRF vulnerabilities due to a lack of token validation in certain actions.
- Numerous bug bounty reports exist where CSRF on actions like password changes, email changes, or account deletions have been found in various applications.

---

## 🔎 Code Review Tips

**What patterns or red flags to look for:**

- **State-changing operations without tokens:** Any `POST`, `PUT`, `DELETE`, or even sensitive `GET` requests (though less common for CSRF) that modify data on the server without including a unique, unpredictable, and user-specific token.
- **Reliance solely on cookie-based authentication:** If authentication is only handled by cookies, CSRF becomes a higher risk.
- **Lack of `SameSite` cookie attribute:** Older or misconfigured applications might not set the `SameSite` attribute for session cookies, making them vulnerable by default.
- **GET requests performing sensitive actions:** If a GET request is used to delete an account, change a password, or transfer funds, it's a huge red flag for CSRF.
- **Requests originating from untrusted domains:** Look for server-side logic that doesn't properly validate the `Referer` or `Origin` headers (though these are not foolproof CSRF defenses).

**Bad vs good code examples (especially Python and TS):**

- **Bad Python (Flask/Django - Missing CSRF Protection):**
    
    
    ``` Python 
    # Flask Example (no CSRF protection)
    from flask import Flask, request, redirect, url_for, session
    
    app = Flask(__name__)
    app.secret_key = 'super_secret_key' # Insecure in production
    
    @app.route('/transfer', methods=['POST'])
    def transfer_funds():
        if 'user_id' not in session:
            return redirect(url_for('login'))
    
        recipient = request.form.get('recipient')
        amount = request.form.get('amount')
    
        # Insecure: No CSRF token check
        # ... perform fund transfer logic ...
        return "Funds transferred successfully!"
    
    # Good Python (Flask with Flask-WTF CSRF protection):
    from flask import Flask, request, redirect, url_for, session, render_template
    from flask_wtf.csrf import CSRFProtect
    from flask_wtf import FlaskForm
    from wtforms import StringField, DecimalField, SubmitField
    from wtforms.validators import DataRequired
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'a_very_secret_key_for_production'
    csrf = CSRFProtect(app)
    
    class TransferForm(FlaskForm):
        recipient = StringField('Recipient', validators=[DataRequired()])
        amount = DecimalField('Amount', validators=[DataRequired()])
        submit = SubmitField('Transfer')
    
    @app.route('/transfer', methods=['GET', 'POST'])
    def transfer_funds():
        form = TransferForm()
        if form.validate_on_submit():
            # Form submission is valid and CSRF token checked by Flask-WTF
            recipient = form.recipient.data
            amount = form.amount.data
            # ... perform fund transfer logic ...
            return "Funds transferred successfully!"
        return render_template('transfer.html', form=form)
    
    # In transfer.html (Jinja2 template):
    # <form method="POST">
    #     {{ form.csrf_token }}
    #     {{ form.recipient.label }} {{ form.recipient() }}<br>
    #     {{ form.amount.label }} {{ form.amount() }}<br>
    #     {{ form.submit() }}
    # </form>
    ```
    
- **Bad TypeScript/Node.js (Express - Missing CSRF Protection):**
    
    TypeScript
    
    ```typescript
    // Insecure Node.js (Express - no CSRF protection)
    import express from 'express';
    import cookieParser from 'cookie-parser';
    
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(cookieParser());
    
    app.post('/change-password', (req, res) => {
        // Assume user is authenticated via session cookie
        const newPassword = req.body.newPassword;
        // Insecure: No CSRF token check
        // ... update password logic ...
        res.send('Password changed successfully!');
    });
    
    // Good TypeScript/Node.js (Express with csurf middleware):
    import express from 'express';
    import cookieParser from 'cookie-parser';
    import session from 'express-session';
    import csurf from 'csurf';
    
    const app = express();
    app.use(cookieParser());
    app.use(session({
        secret: 'your_secret_key',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: true } // Use secure cookies in production
    }));
    
    const csrfProtection = csurf({ cookie: true });
    app.use(csrfProtection); // Apply CSRF protection globally or to specific routes
    
    app.get('/form', (req, res) => {
        // Render a form with the CSRF token
        res.send(`<form action="/change-password" method="POST">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <input type="password" name="newPassword" placeholder="New Password">
            <button type="submit">Change Password</button>
        </form>`);
    });
    
    app.post('/change-password', (req, res) => {
        // CSRF token is automatically validated by csurf middleware
        const newPassword = req.body.newPassword;
        // ... update password logic ...
        res.send('Password changed successfully!');
    });
    
    // Error handling for CSRF
    app.use((err: any, req: any, res: any, next: any) => {
        if (err.code === 'EBADCSRFTOKEN') {
            res.status(403).send('Invalid CSRF token');
        } else {
            next(err);
        }
    });
    ```
    

**What functions/APIs are often involved:**

- **HTTP Methods:** `POST`, `PUT`, `DELETE` (and sometimes `GET` when misused for state changes).
- **Form submissions:** HTML `<form>` tags and their `action` and `method` attributes.
- **JavaScript:** `fetch()`, `XMLHttpRequest`, `form.submit()`, and dynamic DOM manipulation that sends requests.
- **Server-side frameworks:** Functions or middlewares for handling form data, sessions, and request routing (e.g., Flask `request.form`, Django `request.POST`, Express `req.body`).
- **Cookie management:** Setting and reading session cookies.

**Where in the app codebase you'd usually find this:**

- **Route definitions/Controllers:** Where HTTP requests are handled and mapped to specific functions.
- **Form processing logic:** Code that takes user input from forms and performs actions.
- **Authentication/Session management:** How user sessions are managed and linked to requests.
- **Templates/Views:** Where forms are rendered, and where hidden input fields for CSRF tokens would typically be placed.

---

## 🛡️ Mitigation Strategies

**Input validation/sanitization:**

- While crucial for other vulnerabilities (like XSS or Injection), input validation alone does _not_ prevent CSRF. CSRF is about the _origin_ of the request, not its content. However, good validation is still a part of overall web security.

**Encoding/escaping best practices:**

- Not directly applicable to preventing CSRF. Encoding/escaping prevents XSS, which can sometimes be used to _facilitate_ a CSRF attack (e.g., by injecting a malicious form), but it's not a direct CSRF mitigation.

**Framework-specific protections (e.g., React auto-escapes HTML):**

- **CSRF Tokens (Synchronizer Token Pattern):** This is the most common and effective defense.
    
    1. When a user requests a form, the server generates a unique, unpredictable token.
    2. This token is embedded as a hidden field in the HTML form and also stored in the user's session on the server.
    3. When the user submits the form, the server compares the token in the request with the token stored in the session.
    4. If they don't match, the request is rejected. Since an attacker cannot predict the token, they cannot forge a valid request.
    
    - **Framework Support:** Most modern web frameworks provide built-in CSRF protection that implements this pattern:
        - **Django:** Has built-in CSRF protection enabled by default. Requires `{% csrf_token %}` in forms.
        - **Flask:** `Flask-WTF` extension provides easy CSRF integration.
        - **Ruby on Rails:** Includes CSRF protection by default.
        - **ASP.NET Core:** Provides anti-forgery tokens.
        - **Express.js (Node.js):** `csurf` middleware.
- **SameSite Cookie Attribute:**
    
    - This cookie attribute (set on the server) controls whether cookies are sent with cross-site requests.
    - `SameSite=Lax`: Cookies are sent with top-level navigations (e.g., clicking a link) and GET requests, but not with POST requests from different origins. This provides good protection against many CSRF attacks while maintaining user experience.
    - `SameSite=Strict`: Cookies are only sent with requests originating from the same site. This offers the strongest protection but can break functionality for legitimate cross-site requests (e.g., if a user clicks a link from another domain to access your site).
    - `SameSite=None; Secure`: Cookies are sent with all requests, including cross-site, but _only_ if the connection is HTTPS. This option is often used for legitimate cross-site functionality (e.g., if your site embeds content from another origin that needs your cookie). Without `Secure`, `SameSite=None` is often equivalent to not setting `SameSite` at all in terms of security.
    - **Recommendation:** `Lax` is generally a good default. For highly sensitive operations, `Strict` might be considered if it doesn't negatively impact UX.

**Secure configurations (headers, CSPs, etc.):**

- **`Referer` Header Check:** The server can check the `Referer` header to ensure the request originated from the expected domain. However, this is not a strong defense because:
    - Users can disable `Referer` headers.
    - Proxies can strip them.
    - Attackers might sometimes manipulate them.
    - For HTTPS to HTTP requests, the `Referer` is often not sent.
- **`Origin` Header Check:** Similar to `Referer`, the `Origin` header can be checked. It's generally more reliable than `Referer` for AJAX requests but can also be stripped or manipulated in certain scenarios.
- **Content Security Policy (CSP):** While primarily for XSS, a strict CSP can limit the ability of an attacker to load malicious resources (like hidden forms) from untrusted domains, but it's not a direct CSRF defense.

**Defense-in-depth:**

- **Re-authentication for sensitive actions:** For extremely sensitive actions (e.g., changing email, password, making large transfers), prompt the user to re-enter their password. This adds another layer of verification beyond just the session cookie and CSRF token.
- **User UI confirmation:** For critical actions, require the user to explicitly confirm the action via a dialog box.
- **Limit cookie scope:** Use `HttpOnly` on session cookies to prevent JavaScript access, which mitigates XSS-based CSRF. Use the `Secure` flag for HTTPS-only cookies.

---

## 🔐 Blockchain Context (if applicable)

How this vuln appears in smart contracts or crypto wallet code:

CSRF as commonly understood in web applications (browser-based, cookie-reliant) doesn't directly apply to smart contracts or blockchain transactions in the same way. Blockchain transactions are explicitly signed by the user's private key, which is a stronger form of authentication than a session cookie. You can't trick a user's wallet into signing a transaction they didn't intend to.

However, the _spirit_ of CSRF – tricking a user into an unintended action – can manifest in Web3 in different ways, often related to user interface (UI) or wallet interaction.

**Web3-specific risks (e.g., RPC abuse, signing UI attacks):**

- **Wallet Signing UI Attacks (Transaction Phishing/Spoofing):**
    
    - **The Attack:** A malicious DApp or website might present a legitimate-looking transaction request to the user's wallet (e.g., MetaMask). However, the _actual_ details of the transaction (e.g., recipient address, amount, function call) displayed within the wallet's signing UI are manipulated or hidden by the attacker. The user might _think_ they are approving one action (e.g., approving a small amount of token transfer to a legitimate contract) but are actually approving another (e.g., approving unlimited token transfer to an attacker's address, or sending funds to a different address).
    - **Mitigation:**
        - **Wallets:** Wallets are continuously improving their signing UIs to be clearer, show full transaction data, and warn users about suspicious interactions.
        - **Users:** Users must carefully review _all_ details displayed in their wallet's signing prompt before approving a transaction, not just the "pretty" UI on the DApp.
        - **DApps:** DApps should clearly and transparently display the transaction details to the user before prompting for a wallet signature.
- **Blind Signing/Approvals:**
    
    - **The Attack:** This is a risk where users approve transactions without fully understanding what they are signing. This often happens with "approve" functions in ERC-20 tokens, where users might grant a smart contract permission to spend a certain amount (or unlimited amount) of their tokens. If the approved contract later turns out to be malicious or compromised, the attacker can drain the user's funds. While not strictly CSRF, it shares the element of an unintended consequence of a "legitimate-looking" action.
    - **Mitigation:**
        - **DApps:** Encourage and default to "approve" for specific amounts, not unlimited. Educate users.
        - **Wallets/Tools:** Tools like Revoke.cash allow users to review and revoke token approvals.
        - **Users:** Only approve necessary amounts. Regularly review and revoke unnecessary approvals.
- **RPC Abuse/Front-running (less direct CSRF link):**
    
    - This is more related to MEV (Maximal Extractable Value) and network-level attacks. While an attacker isn't directly forcing a user's action via their browser, they can observe pending transactions (via RPC nodes) and then submit their own transaction to "front-run" or "sandwich" the user's transaction for profit. Not CSRF, but related to exploiting the network interaction.

In essence, while the technical vector differs, the core idea of exploiting trust and tricking a user into an unintended action remains a critical security consideration in the Web3 space, primarily shifting from "forged browser requests" to "misleading wallet signing prompts."