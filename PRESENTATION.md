# Project Presentation: OAuth2 PEP for Zero Trust Access

---

### **1. Executive Summary**

This project delivers a **comprehensive OAuth2 Policy Enforcement Point (PEP) architecture** that implements enterprise-grade access control. It is built on **Zero Trust principles** (ANSSI compliant) and integrates with enterprise identity systems via **OpenLDAP**.

The solution provides a centralized authentication gateway that protects backend applications without requiring code modifications, making it ideal for securing both modern and legacy systems.

**Key Deliverables:**
- A fully containerized OAuth2 & OIDC Identity Provider solution.
- Centralized policy enforcement and user authentication within a single, isolated network.
- Secure integration with backend services via HTTP header injection.
- Adherence to security best practices, including the principle of least privilege for network exposition.

---

### **2. Business Objectives**

- **Enhance Security**: Implement a Zero Trust model where every request is verified within a secure network perimeter.
- **Centralize Authentication**: Simplify access management for multiple applications using a single identity source (OpenLDAP).
- **Improve Compliance**: Adhere to industry standards like OAuth2, OIDC, and ANSSI security recommendations.
- **Legacy System Integration**: Provide a non-intrusive way to secure existing applications that lack modern authentication capabilities.

---

### **3. Technical Architecture**

The platform is composed of five core services, orchestrated by Docker Compose within a single bridge network (`172.25.0.0/24`) to ensure network isolation and security.

#### **Core Components:**

| Service | Technology | IP Address | Role |
|---|---|---|---|
| **PEP (Policy Enforcement Point)**| Apache httpd + `mod_auth_openidc`| `172.25.0.40` | The main entry point that intercepts all user requests, enforces OIDC authentication, and proxies authenticated requests to the backend Flask application. It injects user identity information into HTTP headers. |
| **Apache Reverse Proxy** | Apache httpd + `mod_proxy` | `172.25.0.30` | A dedicated routing layer that securely exposes a subset of the internal Dex OIDC endpoints (`/auth`, `/theme`, `/static`, etc.) to the PEP, acting as a controlled gateway. |
| **Dex OIDC Provider** | Dex (CNCF Project) | `172.25.0.20` | An OIDC-compliant identity broker that connects to the OpenLDAP backend and issues tokens. Some endpoints are accessed directly by the PEP, while others are routed through the Apache Reverse Proxy. |
| **OpenLDAP** | OpenLDAP | `172.25.0.10` | The centralized user directory and identity store. |
| **Flask Application** | Flask | `172.25.0.50` | The protected backend service that receives requests only after they have been authenticated by the PEP. |

---

### **4. Authentication and Communication Flow**

The entire authentication process occurs within the secure, isolated Docker network.

1.  A user attempts to access the main entry point at the PEP's IP address (`http://172.25.0.40`).
2.  The PEP, using `mod_auth_openidc`, intercepts the request and determines that the user is not authenticated.
3.  The PEP redirects the user to the Dex authorization endpoint, which is exposed via the **Apache Reverse Proxy** (`http://172.25.0.30/auth`).
4.  The user authenticates against Dex using their LDAP credentials. Dex verifies these credentials with the **OpenLDAP** service.
5.  Upon successful authentication, Dex redirects the user back to the PEP with an authorization code.
6.  The PEP's `mod_auth_openidc` module then communicates directly with Dex's token endpoint (`http://172.25.0.20:5556/token`) to exchange the code for an ID token and an access token.
7.  With a valid token, the PEP proxies the original request to the **Flask Application** (`http://172.25.0.50:8080`), injecting the user's identity (username, email, groups) into the HTTP headers.
8.  The Flask application processes the request and serves content, using the injected headers to display user-specific information.

This architecture ensures that the Flask application remains completely isolated from the public-facing network and only receives traffic that has been vetted and authenticated by the PEP, enforcing a strict Zero Trust policy. 