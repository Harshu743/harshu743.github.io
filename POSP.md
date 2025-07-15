# Principles of Secure Programming: Comprehensive Study Guide
---

## I. Introduction to IT Application and Data Security

### A. Security Goals

* **Authentication**: Verifying someone's identity.
    * **Methods**: Passwords, biometrics (palm scan, iris scan, retinal scan, fingerprinting, voice identification, facial recognition, signature dynamics), multi-factor authentication (MFA).
    * **Types**: Two-factor authentication (something you know + something you have/are), Mutual Authentication (client and server verify each other).
* **Authorization**: Checking if a user has permission to conduct an action (e.g., Access Control List - ACL).
* **Confidentiality**: Keeping data secret from unauthorized access and disclosure.
    * **Techniques**: Data Encryption, Access Control, Secure Communication Protocols (TLS, SSL), Data Masking, Firewalls, Anti-Malware Software, Regular Audits and Monitoring.
* **Data/Message Integrity**: Ensuring data is trustworthy, accurate, and protected from unauthorized changes.
    * **Techniques**: Data Validation and Sanitization, Cryptographic Hash Functions, Digital Signatures, Access Controls, Audit Trails, Secure Communication Protocols, Error Detection and Handling, Version Control, Regular Backups, Message Authentication Codes (MACs).
* **Availability**: Ensuring systems and data are accessible to authorized users when needed.
    * **Techniques**: Redundancy and Failover Systems, Load Balancing, Regular System Updates and Maintenance, Disaster Recovery Plans, Backups, Network Security Measures (DDoS protection), Monitoring and Alerting Systems, Resource Management, Quality of Service (QoS) Controls, Scalability, Employee Training and Awareness.
* **Accountability**: Tracing actions within a system back to responsible entities.
    * **Techniques**: Authentication, Logging, Audit Trails.
* **Non-Repudiation**: Ensuring actions or transactions cannot be denied after they have occurred.
    * **Techniques**: Digital signatures, audit trails, Trusted Third Party (Trent), Key Management, Timestamping and Logging, Verification of Signatures, Dispute Resolution, Archiving.

---

### B. Secure System Design

* **Holistic Security**: Requires physical security, technological security (application, OS, network), and good policies/procedures.
    * **Physical Security**: Locked doors, cameras, card readers, biometric locks, shredding sensitive documents.
    * **Technological Security**:
        * **Application Security**: Secure web servers, handling user identity, robust data interpretation in browsers.
        * **OS Security**: Regular patching to eliminate vulnerabilities (e.g., Windows Update).
        * **Network Security**: Ensuring valid data packets, preventing malicious traffic (e.g., Firewalls, Intrusion Detection Systems - IDSs).
* **Understanding Threats and Attacks**:
    * **Defacement**: Vandalism replacing legitimate web pages with illegitimate ones.
    * **Infiltration**: Unauthorized party gaining full access to system resources.
    * **Phishing**: Spoofed websites luring users to enter credentials.
    * **Pharming**: Malicious code redirecting users to spoofed websites by interfering with DNS.
    * **Denial of Service (DoS)**: Attacker sending excessive packets to make a system unavailable.
    * **Data Theft and Data Loss**: Unauthorized access and extraction or disappearance of sensitive data.
* **Secure Design Principles**:
    * **Least Privilege**: Granting minimum necessary access.
    * **Defense-in-Depth**: Multiple layers of security controls.
    * **Fail-Safe Defaults**: Secure settings by default.
    * **Separation of Duties**: Distributing tasks to prevent single point of control.
    * **Economy of Mechanism**: Simple and straightforward security mechanisms.
    * **Least Common Mechanism**: Minimizing shared resources.
    * **Complete Mediation**: Checking access to resources every time it's attempted.
    * **Open Design**: Security based on well-known principles, not obscurity.
    * **Secure Defaults**: Configuring systems with secure settings as default.
    * **Minimize Trust Surface**: Reducing components or points where trust is required.

---

## II. Secure Software Development Lifecycle (SSDLC)

### A. Importance and Phases of SSDLC

* **Definition**: An enhanced SDLC that integrates security practices at every development phase.
* **Benefits**: Reduces vulnerabilities early (cost-saving), ensures compliance, minimizes cyber threat risks, improves reliability and trust.
* **Phases and Security Considerations**:
    * **Planning & Requirement Analysis**: Identify security requirements (authentication, authorization, data protection, logging, regulatory compliance), secure communication (encryption, VPNs, MFA), perform threat modeling (STRIDE model: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), establish security policies and compliance requirements (GDPR, HIPAA).
    * **Design**: Perform architectural risk analysis, define security controls (authentication, access control), apply security architecture principles (security policies, encryption, network security, endpoint security, least privilege, fail-safe defaults).
    * **Development (Coding)**: Follow secure coding practices (input validation, secure session management, error handling & logging, regular security testing).
    * **Deployment**: Ensure secure configurations and access controls, implement security monitoring and logging, conduct vulnerability scanning.
    * **Maintenance**: Monitor for new vulnerabilities, apply patches, continuously improve security policies, conduct periodic security audits.

---

### B. Secure Coding Practices and Guidelines

* **Importance**: Protects applications from cyber threats, prevents financial/property damages, market manipulation, theft, and physical harm. Maintains customer trust.
* **Practices**:
    * **Authentication and Authorization**: Strong authentication (MFA), role-based access control (RBAC), password policies (salted cryptographic hashes, length/complexity, disable after incorrect attempts).
    * **Input Validation**: Validate and sanitize all input data (syntactical and semantic validation), perform server-side validation (never rely on client-side), validate file uploads (extension, size, "special" files), use validation libraries (e.g., validator.js). Prevents SQL injection, XSS, DoS, buffer overflow, RCE.
    * **Session Management**: Use secure session IDs (generic names, sufficient length, entropy, meaningless content), session timeouts, automatic logout, rotate session IDs after authentication.
    * **Error Handling and Logging**: Avoid leaking sensitive information in error messages, log errors securely with full details internally, provide generic messages externally.
    * **Secure Communication**: Use encrypted protocols (HTTPS, SSL/TLS), avoid hardcoding sensitive info.
    * **Secure Configuration**: Ensure secure defaults, disable unnecessary services, keep software updated (patch management system).
    * **Threat Modeling**: Document, locate, address, and validate threats throughout the lifecycle.
    * **Cryptographic Practices**: Encrypt data with modern algorithms, secure key management.
    * **Least Privilege Principle**: Grant minimum access.
    * **Security by Design**: Integrate security from the beginning, not an afterthought.

---

### C. Code Review and Vulnerability Scanning

* **Code Review**: Manual examination of source code by developers/peers.
    * **Purpose**: Find bugs, security vulnerabilities, coding errors, ensure adherence to standards.
    * **Benefits**: Early detection, improved code quality, consistency, knowledge sharing, collective code ownership, collaboration, documentation, continuous improvement.
    * **Types**: Pull Request (PR) reviews, Pair Programming, Over-the-Shoulder reviews, Tool-Assisted reviews, Email-Based review, Checklist Review, Ad Hoc Review, Formal Inspection.
    * **Process**: Preparation, Reviewer Selection, Environment/Tools, Checklist, Inspection (syntax, logic, performance, security, style, design), Feedback, Discussion, Revisions, Approval, Integration, Follow-Up, Documentation.
    * **Limitations**: Time-consuming, subjectivity, overhead, reviewer bias, communication challenges, skill level dependency, false positives, mental fatigue.
    * **Best Practices**: Clear expectations, right reviewers, small changes, provide context, use tools, focus on quality, check for vulnerabilities, test code, constructive feedback, positive tone, timely reviews, document decisions, continuous learning.
* **Vulnerability Scanning**: Automated tools to identify potential security vulnerabilities.
    * **Purpose**: Detect known vulnerabilities, misconfigurations, weaknesses.
    * **Benefits**: Fast detection of common issues.
    * **Types**:
        * **Static Application Security Testing (SAST)**: "Whitebox" – analyzes source code, bytecode, or binaries without execution. Detects bugs early.
        * **Dynamic Application Security Testing (DAST)**: "Blackbox" – examines the running application from the outside, simulates attacks. Finds flaws in executed code.
        * **Interactive Application Security Testing (IAST)**: Combines SAST and DAST.
        * **Continuous Monitoring**: Ongoing scanning.
    * **Complementary Practices**: Code reviews catch logical flaws and adherence to practices, while vulnerability scanning identifies known weaknesses. Both aim for early detection.

---

### D. Security Testing Methodologies

* **Definition**: Non-functional software testing to check threats, risks, and vulnerabilities.
* **Types**:
    * **Vulnerability Scanning**: (as above) External, Internal, Non-Intrusive, Intrusive.
    * **Penetration Testing**: Simulating a hack under controlled conditions to find hidden vulnerabilities.
        * **Phases**: Pre-engagement, Information gathering/recon, Discovery, Vulnerability analysis, Exploitation and post-exploitation, Report and recommendation, Remediation and rescan.
    * **Risk Assessment**: Identifying and mitigating security risks (Identification, Assessment, Mitigation).
    * **Security Audit**: Comprehensive approach combining automated scanning and manual penetration testing (VAPT).
    * **Secure Code Review**: (as above) Automated (DAST tools) and Manual.
    * **Security Posture Assessment**: Comprehensive assessment of network health and resilience (Identification of assets, determining risks, assessing current measures, planning ROI).
* **Attributes**: Ensuring CIA (Confidentiality, Integrity, Availability), Authentication and Authorization, Non-repudiation, Resilience.

---

## III. Web Application Security

### A. Common Web Application Vulnerabilities

* **Injection Attacks**: Injecting malicious code into input fields or URLs.
    * **SQL Injection**: Injecting malicious SQL commands (e.g., Username: ' OR '1'='1).
    * **Cross-Site Scripting (XSS)**: Injecting malicious scripts into web pages to be executed by other users.
* **Cross-Site Request Forgery (CSRF)**: Tricking a logged-in user into performing an unintended action.

---

### B. Input Validation and Output Encoding

* **Input Validation**: Crucial for preventing injection attacks and other vulnerabilities. (See Secure Coding Practices above).
* **Output Encoding**: Converting potentially malicious characters into a safe format before displaying them, to prevent XSS.

---

### C. Session Management and Cookie Security

* **Session Management**: Maintaining user state across multiple HTTP requests.
    * **Risks**: Session hijacking (attacker takes over an active session), session fixation (attacker sets a user's session ID), unauthorized access.
    * **Mitigation**: Secure session ID generation (length, entropy, meaninglessness), session timeouts, automatic logout, rotation of session IDs after authentication, secure cookie attributes (Secure, HttpOnly, SameSite).
* **Cookie Security**: Protecting cookies from unauthorized access or manipulation.
    * **Cookie Attributes**: Secure (only send over HTTPS), HttpOnly (prevents client-side script access), SameSite (prevents cross-site requests).

---

### D. Web Application Firewalls (WAF)

* **Purpose**: Act as a barrier between web applications and the internet, filtering and monitoring HTTP traffic.
* **Mitigation**: Protects against common web vulnerabilities by inspecting HTTP requests and responses and blocking malicious traffic.

---

### E. Secure APIs and Web Services (SOAP, REST)

* **Importance**: APIs and web services are critical components, especially for sensitive data exchange.
* **Security Features**:
    * **Authentication**: Verifying API client identity (e.g., API keys, OAuth).
    * **Authorization**: Controlling access to specific API resources.
    * **Encryption**: Protecting data in transit (TLS/SSL).
    * **Input Validation**: Sanitizing inputs to prevent injection attacks.
    * **Rate Limiting**: Preventing DoS attacks by limiting request frequency.
    * **Logging and Monitoring**: Tracking API usage and detecting anomalies.
* **SOAP Security**: Utilizes XML-based security standards (WS-Security).
* **REST Security**: Relies on transport layer security (HTTPS) and authentication mechanisms like OAuth 2.0.

---

## IV. Identity and Access Management (IAM)

### A. IAM Principles and Components

* **Definition**: A framework of policies, processes, and technologies to manage digital identities and control user access.
* **Purpose**: Stop hackers while allowing authorized users appropriate access.
* **Benefits**: Improves security and user experience, enables mobile/remote working, facilitates cloud adoption, reduces help desk requests (password resets), reduces risk (data breaches), helps meet compliance.
* **Core Components**:
    * **Identity Lifecycle Management**: Creating and maintaining digital user identities (human and nonhuman) in a central database (source of truth). Differentiating users and assigning attributes.
    * **Access Control**: Setting and enforcing granular access policies based on distinct digital identities.
    * **Role-Based Access Control (RBAC)**: Privileges based on job function and responsibility, streamlining permissions and mitigating excessive privileges (principle of least privilege).
    * **Privileged Access Management (PAM)**: Oversees account security for highly privileged users (high-value targets).
    * **Zero-Trust**: Assumes every connection and endpoint is a threat, regardless of network location. Requires continuous assessment and verification. IAM is crucial for this approach (SSO, MFA, lifecycle management).
    * **Authentication and Authorization**:
        * **Authentication**: Verifying who a user claims to be using credentials (password, digital certificate, MFA).
        * **Authorization**: Granting access based on authenticated identity's privileges.
    * **Identity Governance**: Tracking user activity with access rights to ensure compliance (GDPR, PCI-DSS) and detect abuse. Produces audit trails.

---

### B. User Authentication and Authorization Mechanisms

* **Authentication Mechanisms**:
    * **Passwords**: Basic but weakest form.
    * **Multi-Factor Authentication (MFA)**: Requires multiple factors (something you know, something you have, something you are).
        * **Types**: SMS/Email Codes, Authentication Apps, Hardware Tokens, Biometric Authentication, Push Notifications.
    * **Risk-Based Authentication/Adaptive Authentication**: Assesses risk based on context (device, IP, location) to decide authentication level.
* **Authorization Mechanisms**:
    * **Access Control Lists (ACLs)**: Used by OS to determine user permissions for actions.
    * **Role-Based Access Control (RBAC)**: Assigning permissions based on user roles.

---

### C. Single Sign-On (SSO) and Federation

* **Single Sign-On (SSO)**: Authenticate once and access multiple applications/systems with one set of credentials.
    * **Benefits**: Enhanced user experience, reduced password fatigue, simplified password management, minimized security risks, improved identity protection.
    * **Mechanism**: Relies on a trusted third party to verify identity (e.g., SAML, OAuth).
* **Federated Identity Management**: Authentication-sharing process where businesses share digital identities with trusted partners, allowing users to use multiple services with the same credentials. SSO is an example.
* **Cloud Identity and Access Management (IDaaS/AaaS)**: Cloud-based IAM solutions offering flexibility for distributed users and resources, and allowing outsourcing of IAM tasks.

---

## Quiz: Principles of Secure Programming

Answer each question in 2-3 sentences.

1.  What is the primary distinction between "**authentication**" and "**authorization**" in the context of secure programming?
2.  Briefly explain the principle of "**Least Privilege**" in secure system design and why it is important.
3.  Describe the concept of "**Data Integrity**" as a security goal and provide one technique to maintain it.
4.  What is the main purpose of a "**Web Application Firewall (WAF)**"?
5.  Explain the concept of "**Zero-Trust**" architecture and its relationship with Identity and Access Management (IAM).
6.  How does "**Multi-Factor Authentication (MFA)**" enhance security beyond a simple username and password?
7.  What is "**SQL Injection**" and how can secure coding practices mitigate this vulnerability?
8.  Briefly describe "**Dynamic Application Security Testing (DAST)**" and what kind of vulnerabilities it aims to find.
9.  Why is "**server-side input validation**" considered critical in secure coding, as opposed to client-side validation?
10. What is "**Non-repudiation**" and how does "**Trent**" (a trusted third party) contribute to achieving it?

---

## Answer Key for Quiz

1.  **Authentication** is the process of verifying a user's identity, confirming they are who they claim to be. **Authorization**, on the other hand, determines what actions an authenticated user is permitted to perform within the system based on their granted permissions.
2.  The principle of **Least Privilege** dictates that users, processes, or systems should only be granted the minimum level of access or permissions necessary to perform their specific tasks. This is crucial because it significantly reduces the potential impact and scope of a security breach if an account or process is compromised.
3.  **Data Integrity** is the security goal that ensures information remains accurate, consistent, and protected from unauthorized modification or destruction. One technique to maintain it is the use of cryptographic hash functions, which generate a unique value for data, revealing any alterations if the hash changes.
4.  The main purpose of a **Web Application Firewall (WAF)** is to protect web applications by filtering and monitoring incoming and outgoing HTTP traffic. It acts as a shield, preventing common web application vulnerabilities like injection attacks and XSS from reaching the application.
5.  **Zero-Trust** is a security framework that operates on the assumption that no user or device, whether inside or outside the network, should be implicitly trusted. **Identity and Access Management (IAM)** is crucial to Zero-Trust as it enables continuous assessment and verification of identities accessing resources, enforcing strict access controls.
6.  **Multi-Factor Authentication (MFA)** enhances security by requiring users to provide two or more verification factors from different categories (e.g., something they know, something they have, something they are). This makes it significantly harder for attackers to gain access, even if they compromise one factor like a password.
7.  **SQL Injection** is a web application vulnerability where an attacker inserts malicious SQL code into input fields to manipulate database queries or gain unauthorized access. Secure coding practices like input validation and sanitization (e.g., using parameterized queries or escaping harmful characters) are crucial to prevent this by treating user input as data, not executable code.
8.  **Dynamic Application Security Testing (DAST)** is a security testing methodology that examines a running application from the outside, simulating attacks to discover vulnerabilities. It aims to find flaws that manifest during runtime, such as configuration errors, authentication bypasses, or issues in the application's overall behavior when interacting with external inputs.
9.  **Server-side input validation** is critical because client-side validation can be easily bypassed by attackers, who can manipulate client-side scripts to send malicious input directly to the server. Performing validation on the server ensures that all input, regardless of its origin, is rigorously checked for validity, integrity, and safety before processing.
10. **Non-repudiation** is the assurance that a party in a communication or transaction cannot deny the authenticity of their signature or the sending/receiving of a message. **Trent**, as a trusted third party, contributes by providing an independent and verifiable record or evidence (e.g., timestamps, digital signatures) that can be used to prove the involvement of parties, thus ensuring undeniability.

---

## Essay Format Questions

1.  Discuss the critical role of integrating security into every phase of the Software Development Lifecycle (SDLC) to create a **Secure SDLC (SSDLC)**. Provide specific examples of security considerations and activities that should be performed at each major phase (e.g., Planning, Design, Development, Deployment, Maintenance), explaining how these contribute to overall application security and cost reduction.
2.  Compare and contrast the three core security goals of **Confidentiality, Integrity, and Availability (CIA triad)**. For each goal, provide a real-world scenario where its compromise would lead to significant harm, and explain at least two distinct technological measures or practices that organizations can implement to achieve and maintain that specific security goal.
3.  Analyze the importance of robust **input validation** and **secure session management** in mitigating common web application vulnerabilities. Explain how improper handling of each can lead to specific attacks (e.g., SQL Injection, XSS, session hijacking, session fixation), and detail the secure coding practices and guidelines developers should follow to prevent these vulnerabilities.
4.  Evaluate the "**Zero-Trust**" security framework, discussing its fundamental principles and why it has become increasingly relevant in modern IT environments. Explain how **Identity and Access Management (IAM)** initiatives, including specific mechanisms like Multi-Factor Authentication (MFA) and Single Sign-On (SSO), are crucial for successfully implementing a Zero-Trust architecture.
5.  Distinguish between **Static Application Security Testing (SAST)** and **Dynamic Application Security Testing (DAST)** as methodologies for identifying vulnerabilities. Discuss their respective advantages and limitations, and explain why a comprehensive security strategy often requires the combination of both approaches, along with human-led code reviews.

---

## Glossary of Key Terms

* **Accountability**: The security goal ensuring that actions within a system can be traced back to responsible entities, typically achieved through logging and audit trails.
* **Access Control List (ACL)**: A list of permissions associated with a system resource, specifying which users or system processes are granted access to the resource and what operations they are allowed to perform.
* **Application Security**: The measures taken to protect software applications from threats throughout their lifecycle, including secure coding practices and vulnerability management.
* **Authentication**: The process of verifying a user's, device's, or system's identity, confirming they are who they claim to be.
* **Authorization**: The process of determining whether an authenticated user or system has the necessary permissions to access a particular resource or perform a specific action.
* **Availability**: The security goal ensuring that systems, applications, and data are accessible to authorized users when needed, protected against disruptions.
* **Buffer Overflow**: A security vulnerability where a program attempts to write data beyond the allocated size of a buffer, potentially overwriting adjacent memory and leading to crashes or arbitrary code execution.
* **Confidentiality**: The security goal ensuring that sensitive information is accessible only to authorized individuals or systems, preventing unauthorized disclosure.
* **Cookie Security**: Practices and attributes (e.g., Secure, HttpOnly, SameSite) applied to HTTP cookies to protect them from unauthorized access, tampering, or misuse, especially in web applications.
* **Code Review**: The manual examination of source code by developers or peers to identify bugs, security vulnerabilities, coding errors, and ensure adherence to coding standards.
* **Complete Mediation**: A secure design principle requiring that every attempted access to a resource be checked for authorization, rather than assuming prior permissions are still valid.
* **Cross-Site Request Forgery (CSRF)**: A web application vulnerability that tricks a logged-in user into performing an unintended action on a trusted site by including a malicious link or script on a different site.
* **Cross-Site Scripting (XSS)**: A web application vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users, typically to steal session cookies or deface websites.
* **Cryptographic Hash Function**: A mathematical algorithm that takes an input (or 'message') and returns a fixed-size string of bytes, typically used to ensure data integrity by detecting any changes to the input.
* **Data Integrity**: The security goal ensuring that data is trustworthy, accurate, and protected from unauthorized changes, maintaining its reliability and correctness.
* **Data Masking**: A technique used to obscure sensitive data by replacing it with realistic, but non-sensitive, data to protect confidentiality in non-production environments.
* **Defense-in-Depth**: A secure design principle advocating for multiple layers of security controls throughout a system, so that if one layer fails, others can still provide protection.
* **Denial of Service (DoS) Attack**: A cyber-attack aimed at making a machine or network resource unavailable to its legitimate users by overwhelming it with excessive traffic or requests.
* **Digital Signatures**: Cryptographic mechanisms used to verify the authenticity and integrity of digital documents or messages, ensuring the data hasn't been altered and proving the sender's identity (non-repudiation).
* **Dynamic Application Security Testing (DAST)**: A "blackbox" security testing methodology that examines a running application from the outside by simulating attacks, identifying vulnerabilities that manifest during runtime.
* **Economy of Mechanism**: A secure design principle stating that security mechanisms should be as simple and straightforward as possible to minimize potential vulnerabilities and ease testing.
* **Federated Identity Management**: An authentication-sharing process that allows users to use the same digital identity and credentials to access services across multiple, independent organizations or domains.
* **Fail-Safe Defaults**: A secure design principle where systems and applications are configured to operate with the most secure settings by default, minimizing risk if explicit configurations are not set.
* **Identity and Access Management (IAM)**: A framework of policies, processes, and technologies that enables organizations to manage digital identities and control user access to resources.
* **Identity Governance**: The process within IAM of tracking what users do with their access rights, monitoring for abuse, ensuring regulatory compliance, and producing audit trails.
* **Identity Lifecycle Management**: The process of creating, maintaining, and eventually de-provisioning digital user identities (human and nonhuman) within a system.
* **Infiltration**: An attack in which an unauthorized party gains full access to the resources of a computer system.
* **Input Validation**: A secure coding practice of checking input data for validity, integrity, and safety (e.g., type, length, format, range) before processing it, crucial for preventing injection attacks.
* **Intrusion Detection System (IDS)**: A security tool that monitors network or system activities for malicious activity or policy violations and generates alerts.
* **Least Common Mechanism**: A secure design principle aiming to minimize shared resources or mechanisms among different users or components to limit the potential impact of a security breach.
* **Least Privilege**: A fundamental secure design principle and IAM concept that dictates granting users or processes only the minimum level of access or permissions they need to perform their tasks.
* **Load Balancing**: A technique used to distribute network or application traffic across multiple servers, optimizing resource use, maximizing throughput, and ensuring availability by preventing overload.
* **Message Authentication Code (MAC)**: A cryptographic checksum generated using a secret key, used to provide both data integrity and authentication for a message.
* **Multi-Factor Authentication (MFA)**: An authentication method that requires users to provide two or more distinct verification factors from different categories (e.g., something you know, something you have, something you are) to gain access.
* **Mutual Authentication**: An authentication process where both the client and the server verify each other's identity before establishing a secure communication channel.
* **Network Security**: Measures taken to protect computer networks and data from unauthorized access, misuse, modification, or denial.
* **Non-Repudiation**: The security goal ensuring that a party in a communication or transaction cannot later deny having sent a message or performed an action.
* **OS Security**: The measures and practices involved in securing an operating system against vulnerabilities, including regular patching and proper configuration.
* **Open Design**: A secure design principle stating that the security of a system should not rely on the secrecy of its design or implementation details, but rather on the inherent strength of its underlying principles and mechanisms.
* **Penetration Testing**: A simulated cyber-attack against a computer system, network, or web application to find exploitable vulnerabilities, often conducted by security experts.
* **Pharming**: An online fraud technique that redirects users to spoofed websites, even if they enter the correct URL, typically by interfering with DNS resolution.
* **Phishing**: A social engineering attack where attackers attempt to trick individuals into revealing sensitive information (like login credentials) by masquerading as a trustworthy entity in electronic communication.
* **Privileged Access Management (PAM)**: A cybersecurity discipline within IAM that focuses on managing and securing accounts with elevated permissions, which are high-value targets for attackers.
* **Risk-Based Authentication (RBA) / Adaptive Authentication**: An authentication approach that assesses contextual factors (e.g., device, location, IP address) during a login attempt to determine the risk level and dynamically adjust the authentication requirements.
* **Role-Based Access Control (RBAC)**: An access control model where permissions are assigned to specific roles (e.g., "Administrator," "User"), and users are then assigned to roles, streamlining access management and enforcing least privilege.
* **Secure APIs and Web Services**: Designing and implementing Application Programming Interfaces (APIs) and web services (like SOAP and REST) with security considerations to protect data exchange and functionality.
* **Secure Coding Practices**: A set of principles and techniques used during software development to minimize security vulnerabilities and protect against various cyber threats.
* **Secure Software Development Lifecycle (SSDLC)**: An enhanced version of the traditional SDLC that integrates security activities and considerations into every phase of the software development process.
* **Security Audit**: A comprehensive review of an organization's security posture, often combining automated vulnerability scanning with manual penetration testing.
* **Security Goals**: Fundamental objectives that guide the design, implementation, and evaluation of secure systems, including Confidentiality, Integrity, Availability, Authentication, Authorization, Non-repudiation, and Accountability.
* **Session Management**: The mechanism used in web applications to maintain state and track user interactions across multiple stateless HTTP requests.
* **Single Sign-On (SSO)**: An authentication method that allows users to log in once with a single set of credentials to access multiple independent software applications or systems.
* **SQL Injection**: A common web application vulnerability where an attacker manipulates database queries by inserting malicious SQL code into input fields.
* **Static Application Security Testing (SAST)**: A "whitebox" security testing methodology that analyzes an application's source code, bytecode, or binaries without executing it, typically used to find vulnerabilities early in the development cycle.
* **Threat Modeling**: A structured process used to identify, analyze, and mitigate potential security threats and vulnerabilities in a system during its design and development phases.
* **Trent**: In the context of non-repudiation, a term for a trusted third party (TTP) whose involvement provides an undeniable record or evidence of a transaction or communication.
* **Two-Factor Authentication (2FA)**: A type of MFA that requires two distinct factors for verification, typically "something the user knows" (e.g., password) and "something the user has" (e.g., phone, hardware token).
* **Vulnerability Scanning**: An automated process using tools to identify known security vulnerabilities, misconfigurations, or weaknesses in applications, networks, or systems.
* **Web Application Firewall (WAF)**: A security solution that monitors, filters, and blocks HTTP traffic to and from a web application, protecting against common web-based attacks.
* **Zero-Trust**: A security framework that assumes no implicit trust is granted to any user or device, regardless of their location on the network. All access requests are continuously verified.
