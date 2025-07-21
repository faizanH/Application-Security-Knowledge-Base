## 1. 💡 Core Concepts & Purpose

- **What is it?** Cloud Security (in the context of AWS) refers to the practices, policies, and technologies designed to protect cloud-based applications, data, and infrastructure from threats. It's about ensuring confidentiality, integrity, and availability within the AWS environment.
    
- **Key Components/Elements:**
    
    - **Identity and Access Management (IAM):** Users, Roles, Policies, Groups, Permissions.
        
    - **Compute:** EC2, Lambda, ECS/EKS (Containers).
        
    - **Storage:** S3, EBS, RDS.
        
    - **Networking:** VPC, Subnets, Security Groups, Network ACLs, Route Tables, Direct Connect, VPN.
        
    - **Databases:** RDS, DynamoDB, Aurora.
        
    - **Logging & Monitoring:** CloudTrail, CloudWatch, GuardDuty.
        
    - **Key Management:** KMS, Secrets Manager.
        
    - **Application Services:** API Gateway, Load Balancers, WAF.
        
    - **Shared Responsibility Model:** The fundamental concept defining security roles between AWS and the customer.
        
- **Why does it exist? What's its primary function?** Cloud security exists to extend traditional on-premises security controls to the dynamic, distributed, and scalable nature of cloud environments. Its primary function is to secure applications and data in the cloud by managing access, protecting infrastructure, ensuring compliance, and detecting threats, all while leveraging the cloud provider's managed services.
    

## 2. 🔒 Importance for AppSec & Pentesting

- **Why is understanding this critical for security professionals?** Applications are increasingly deployed in cloud environments. Understanding AWS security is critical because it defines the attack surface, available security controls, and potential misconfigurations that directly impact application security. For AppSec professionals, it's essential to design, build, and integrate applications securely within the cloud framework. For pentesters, it's vital for discovering cloud misconfigurations, leveraging compromised application access for lateral movement, and understanding how cloud services can be abused.
    
- **How does it underpin application security?**
    
    - **Identity & Access:** Application authentication and authorization often rely on underlying IAM roles and policies to access cloud resources (e.g., an EC2 instance assuming a role to write to S3). Misconfigured IAM can lead to privilege escalation or data exfiltration.
        
    - **Network Security:** VPCs, Security Groups, and Network ACLs directly protect application components (EC2 instances, databases) from unauthorized network access.
        
    - **Data Protection:** Cloud storage services (S3, RDS) integrate with encryption services (KMS) for data at rest. Application logic needs to correctly use these services.
        
    - **Logging & Monitoring:** Cloud-native logging (CloudTrail, CloudWatch) provides critical visibility into application-related API calls and helps detect security incidents.
        
    - **Serverless:** For serverless applications (Lambda), the security of the application is inextricably tied to the Lambda execution role and its network configuration.
        
- **What security boundaries/mechanisms does it provide or interact with?**
    
    - **IAM Policies:** Define explicit permissions for human users and machine identities (roles).
        
    - **Resource Policies:** Policies attached directly to resources like S3 buckets or KMS keys.
        
    - **Security Groups/Network ACLs:** Act as virtual firewalls at the instance or subnet level.
        
    - **VPC Boundaries:** Isolate network environments.
        
    - **KMS Key Policies:** Control access to cryptographic keys.
        
    - **CloudTrail Logs:** Audit trail of all API activity.
        

## 3. 😈 Common Security Weaknesses & Attack Vectors

- **Common Misconfigurations/Insecure Defaults:**
    
    - **Public S3 Buckets:** Often misconfigured to allow public read/write access.
        
    - **Overly Permissive IAM Policies:** Granting `*` permissions or `s3:*` on all resources, leading to least privilege violations.
        
    - **Unrestricted Security Group Rules:** Allowing ingress from `0.0.0.0/0` (anywhere) to sensitive ports (e.g., SSH, RDP, database ports).
        
    - **Unpatched OS/Software on EC2:** Not keeping underlying operating systems and installed software updated.
        
    - **Unrestricted Outbound Traffic:** Allowing compromised instances to communicate freely with the internet.
        
    - **Logging Disabled/Misconfigured:** CloudTrail not enabled, or logs not sent to a secure, centralized location.
        
    - **Root Account Usage:** Using the AWS root account for daily operations instead of IAM users/roles.
        
    - **No MFA on Root/High-Privilege Accounts:** Lack of Multi-Factor Authentication.
        
- **Vulnerability Types & Exploitation Methodologies:**
    
    - **Data Breach (via S3/DB):** Exploiting public S3 buckets or misconfigured database access to exfiltrate sensitive data.
        
    - **Credential Theft/Privilege Escalation:**
        
        - **SSRF (Server-Side Request Forgery) to IMDS:** An application vulnerability (like SSRF) allows an attacker to make requests to the EC2 Instance Metadata Service (IMDS) to steal temporary IAM role credentials.
            
        - **IAM Role Exploitation:** Abusing overly permissive IAM roles attached to compromised services (e.g., a Lambda function with `s3:GetObject` on sensitive buckets).
            
    - **Lateral Movement:** Using stolen credentials or a foothold on one compromised resource to access other internal AWS resources (EC2 instances, RDS, internal APIs).
        
    - **Denial of Service:** Exploiting misconfigured Auto Scaling Groups, resource limits, or billing limits.
        
    - **Resource Hijacking:** Launching unauthorized EC2 instances for crypto mining using compromised credentials.
        
    - **Logging Bypass/Tampering:** If CloudTrail logs are not immutable or sent to a secure S3 bucket, an attacker might try to disable or tamper with them.
        
- **Relevant Attack Tools:**
    
    - **AWS CLI/SDKs:** For interacting with compromised AWS accounts.
        
    - **Cloud-specific Reconnaissance:** `aws-cli`, `pacu`, `scoutsuite`, `prowler`.
        
    - **Network Scanning:** Nmap (for open ports on EC2 instances).
        
    - **SSRF Tools:** Burp Suite, `curl`.
        
    - **Credential/Token Abuse:** `aws-vault`, `sts-scan`.
        

## 4. 🛡️ Common Security Controls & Mitigations

- **Basic Security Posture/Best Practices:**
    
    - **Implement the Shared Responsibility Model:** Understand what AWS secures (of the cloud) and what you secure (in the cloud).
        
    - **Least Privilege:** Apply to all IAM users, roles, and policies.
        
    - **Multi-Factor Authentication (MFA):** Enforce for root and all privileged IAM users.
        
    - **Regular Patching:** Keep OS, applications, and dependencies on EC2 instances updated.
        
    - **Centralized Logging:** Enable CloudTrail in all regions, aggregate logs to a central, immutable S3 bucket in a separate logging account.
        
    - **Security Monitoring:** Use GuardDuty, Security Hub, and CloudWatch Alarms.
        
    - **Secure Defaults:** Always configure S3 buckets as private, and enable default encryption.
        
- **Technical Controls:**
    
    - **IAM:** Granular policies, IAM roles for EC2/Lambda, Session Tags, IAM Access Analyzer.
        
    - **Network Security:**
        
        - **VPC & Subnets:** Isolate workloads using private subnets for sensitive resources (DBs).
            
        - **Security Groups:** Statefull, deny-by-default virtual firewalls at the instance level. Restrict ingress/egress to specific ports/IPs/Security Groups.
            
        - **Network ACLs (NACLs):** Stateless firewalls at the subnet level (additional layer).
            
        - **VPC Endpoints:** Private connectivity to AWS services (S3, KMS) without traversing the public internet.
            
        - **IMDSv2:** Enforce IMDSv2 to protect against SSRF to metadata service.
            
    - **Data Protection:**
        
        - **S3 Encryption:** SSE-KMS (recommended for customer-managed keys).
            
        - **KMS:** Manage CMKs, enable automatic key rotation, define strict key policies.
            
        - **Secrets Manager/Parameter Store:** Securely store and retrieve application secrets and configuration data.
            
    - **Application Services:**
        
        - **WAF (AWS WAF):** Protects against common web exploits (OWASP Top 10) at the edge.
            
        - **API Gateway:** Provides authentication, authorization (Lambda Authorizers, Cognito User Pools), throttling, and validation.
            
- **Secure Design Principles:**
    
    - **Infrastructure as Code (IaC):** Define all AWS resources (VPCs, S3 buckets, IAM roles, Security Groups) as code (CloudFormation, Terraform, AWS CDK) to ensure consistent, auditable, and secure deployments.
        
    - **Automated Security Checks in CI/CD:** Integrate SAST, DAST, SCA, and IaC security scanning tools (e.g., Checkov, Terrascan) into your pipeline.
        
    - **Account Segmentation:** Use multiple AWS accounts to separate workloads (e.g., production, development, logging, security tooling).
        
    - **Data Classification:** Classify data sensitivity to apply appropriate security controls.
        
    - **Immutable Infrastructure:** Deploy new instances/containers with updated configurations rather than patching existing ones in place.
        
    - **Zero Trust Networking:** Assume no network is inherently trusted; verify every connection.
        

## 5. 🤝 How it Ties into AppSec/Pentesting Scenarios

- **Enhancing Vulnerability Identification:**
    
    - "Understanding AWS IAM helps identify **Broken Access Control (A01)** by examining whether IAM policies or S3/KMS resource policies are overly permissive, allowing unauthorized access to data or services by authenticated or even unauthenticated users."
        
    - "Knowledge of AWS networking (Security Groups, NACLs, VPC endpoints) helps identify **Insecure Misconfigurations (A05)**, like open ports exposing sensitive services directly to the internet, or enabling paths for internal network access to critical backend components."
        
    - "AWS knowledge is crucial for finding **SSRF (A10)** opportunities. If an application makes outbound HTTP requests based on user input, I'd immediately try to access `http://169.254.169.254/latest/meta-data/` to try and steal temporary EC2 credentials."
        
- **Facilitating Exploitation/Escalation:**
    
    - "If an AppSec vulnerability (e.g., an **Injection flaw (A03)** leading to RCE on an EC2 instance) provides initial access, AWS knowledge guides **privilege escalation** attempts by looking for the instance's IAM role and enumerating its permissions to find overly permissive actions like `s3:*` or `iam:PassRole`."
        
    - "Understanding AWS networking is key for **lateral movement** after compromising a perimeter web server. I'd attempt to map the internal VPC network, identify other EC2 instances, RDS databases, or internal APIs that are accessible from the compromised host, allowing me to pivot deeper into the environment."
        
    - "Exploiting **Vulnerable and Outdated Components (A06)** on a cloud instance might give me RCE, and then my AWS knowledge lets me leverage that RCE to steal cloud credentials and perform actions directly against other AWS services, leading to a much broader compromise than just the single server."
        
- **Proposing Comprehensive Mitigations:**
    
    - "For **Cryptographic Failures (A02)** related to data at rest, I would immediately recommend enforcing **SSE-KMS on S3 buckets** and using AWS KMS for all key management, abstracting the complexity from the application."
        
    - "To mitigate **Insecure Design (A04)** leading to lack of trust boundaries, I'd propose **strong VPC network segmentation** with strict Security Group rules to isolate application tiers (web, app, DB) and sensitive services, ensuring deny-by-default network policies."
        
    - "For **Security Logging and Monitoring Failures (A09)**, leveraging **AWS CloudTrail for all API activity** and streaming logs to **CloudWatch Logs** (and then to a SIEM) is fundamental for detection and incident response."
        
- **Discussing Secure Design:**
    
    - "When designing a new cloud application, adopting **Infrastructure as Code (IaC)** is paramount. It allows us to define security configurations (IAM roles, Security Groups, S3 policies) in code, making them version-controlled, auditable, and less prone to manual misconfigurations."
        
    - "Building on the **Shared Responsibility Model**, we prioritize our 'security _in_ the cloud' responsibilities, focusing on least privilege IAM, hardened AMIs, and secure application code, while trusting AWS for the 'security _of_ the cloud'."
        

## 6. 📚 Key Terms & Concepts (Glossary/Flashcards)

- **IAM:** Identity and Access Management
    
- **CMK:** Customer Master Key (in KMS)
    
- **DEK:** Data Encryption Key (used for actual data encryption)
    
- **KEK:** Key Encryption Key (CMK acts as this for DEKs)
    
- **S3:** Simple Storage Service (Object Storage)
    
- **KMS:** Key Management Service
    
- **VPC:** Virtual Private Cloud (isolated network)
    
- **Security Group:** Virtual firewall for instances/resources
    
- **Network ACL (NACL):** Stateless firewall for subnets
    
- **EC2:** Elastic Compute Cloud (Virtual Servers)
    
- **Lambda:** Serverless compute service
    
- **ECS/EKS/Fargate:** Container orchestration services
    
- **RDS:** Relational Database Service
    
- **DynamoDB:** NoSQL database service
    
- **CloudTrail:** API activity logging service
    
- **CloudWatch:** Monitoring and logging service
    
- **GuardDuty:** Threat detection service
    
- **AWS WAF:** Web Application Firewall
    
- **SSRF:** Server-Side Request Forgery
    
- **IMDS:** Instance Metadata Service (v1, v2)
    
- **Shared Responsibility Model:** AWS's and customer's security duties.
    
- **Least Privilege:** Granting minimum necessary permissions.
    
- **IaC:** Infrastructure as Code (e.g., CloudFormation, Terraform).
    
- **AMI:** Amazon Machine Image (base image for EC2).
    
- **Resource Policy:** Policy attached directly to a resource (like S3 bucket policy, KMS key policy).
    
- **Trust Policy:** Defines who can _assume_ an IAM role.
    
- **Access Analyzer:** Helps identify public and cross-account access.