# Multi-Network Architecture - Zero Trust Segmentation

## Architecture Overview

This project implements a **3-tier network segmentation** architecture following Zero Trust principles, isolating services by function and security level.

Docker Network (DNS-based)
├── external-network
│   ├── apache-reverse-proxy - Apache Reverse Proxy (Entry Point)
│   └── pep - PEP (User Interface)
│
├── backend-network
│   ├── ldap-server - OpenLDAP (Identity Store - INTERNAL ONLY)
│   ├── dex-server - Dex (OIDC Provider - INTERNAL ONLY)
│   └── apache-reverse-proxy - Apache Proxy (Backend Interface)
│
└── app-network
    ├── pep - PEP (App Interface)
    └── flask-application - Flask Application (Business Logic)

## Network Configuration

### External Network (DMZ) - `172.25.0.0/24`
- **Purpose**: Public-facing services
- **Security Level**: External
- **Internet Access**: Yes
- **Services**:
  - Apache Reverse Proxy (port 80 exposed)
  - PEP (port 5000 exposed)

### Backend Network (Infrastructure) - `172.25.1.0/24`
- **Purpose**: Core infrastructure services
- **Security Level**: Internal
- **Internet Access**: **NONE** (internal: true - ZERO TRUST)
- **Services**:
  - OpenLDAP (internal communication only - SECURITY ENHANCED)
  - Dex OIDC Provider (internal only)
  - Apache Proxy (backend interface)

### Application Network (Protected) - `172.25.2.0/24`
- **Purpose**: Business logic applications
- **Security Level**: Protected
- **Internet Access**: **NONE** (internal: true)
- **Services**:
  - Flask Application (completely isolated)
  - PEP (application interface)

## Security Features

### Network Isolation
- ✅ **Zero External Access** to Application Network
- ✅ **Zero External Access** to Backend Infrastructure (SECURITY ENHANCED)
- ✅ **DMZ Isolation** for public services only
- ✅ **Multi-NIC Configuration** for cross-network communication

### Access Control
- 🛡️ **Principle of Least Privilege**: Services only access required networks
- 🛡️ **Defense in Depth**: Multiple security layers
- 🛡️ **Network Segmentation**: Compromise of one network doesn't affect others
- 🛡️ **LDAP Protection**: No direct internet access to identity store

### Communication Flow
```
User Request → External Network (PEP) → Application Network (Flask)
                ↓
Authentication → Backend Network (Dex) → Backend Network (LDAP)
                ↑
        ZERO INTERNET ACCESS TO BACKEND
```

## Service Communication Matrix

| From Service | To Service | Network Path | Purpose | Internet Access |
|--------------|------------|--------------|---------|-----------------|
| **User** | PEP (pep) | External → External | Web Interface | ✅ Yes |
| **PEP** | Apache Proxy (apache-reverse-proxy) | External → External | OAuth2 Auth | ✅ Yes |
| **Apache Proxy** | Dex (dex-server) | External → Backend | OIDC Endpoints | ❌ Internal Only |
| **Dex** | LDAP (ldap-server) | Backend → Backend | User Validation | ❌ Internal Only |
| **PEP** | Flask (flask-application) | External → Application | App Requests | ❌ Internal Only |

## Docker Compose Networks

```yaml
networks:
  external-network:
    driver: bridge
    name: idp-external
    ipam:
      config:
        - subnet: 172.25.0.0/24
          gateway: 172.25.0.1
    labels:
      - "purpose=dmz"
      - "security.level=external"

  backend-network:
    driver: bridge
    name: idp-backend
    internal: true  # ZERO TRUST: No external access to infrastructure
    ipam:
      config:
        - subnet: 172.25.1.0/24
          gateway: 172.25.1.1
    labels:
      - "purpose=backend"
      - "security.level=internal"
      - "zero-trust=enabled"

  app-network:
    driver: bridge
    name: idp-application
    internal: true  # NO external access
    ipam:
      config:
        - subnet: 172.25.2.0/24
          gateway: 172.25.2.1
    labels:
      - "purpose=application"
      - "security.level=protected"
```

## Validation Results

### ✅ Connectivity Tests
- **External Access**: PEP responds with OAuth2 redirect (302)
- **Network Isolation**: Direct Flask access blocked (403)
- **Backend Security**: LDAP and Dex not accessible from internet
- **Service Communication**: Inter-network routing functional

### ✅ Security Validation
- **DMZ Protection**: Only authorized services exposed
- **Backend Isolation**: Infrastructure services completely protected
- **Application Isolation**: Flask completely isolated from internet
- **LDAP Security**: No direct internet access to identity store

### ✅ Zero Trust Compliance
- **Never Trust, Always Verify**: Every network boundary protected
- **Least Privilege Access**: Minimal cross-network communication
- **Micro-segmentation**: Services isolated by function
- **Infrastructure Protection**: No direct access to backend services

## Benefits

1. **Enhanced Security Posture**
   - Reduced attack surface (LDAP no longer exposed)
   - Containment of security breaches
   - Defense in depth implementation
   - Protection against identity enumeration attacks

2. **Compliance Alignment**
   - ANSSI Zero Trust guidelines
   - Network segregation best practices
   - Audit trail through network boundaries
   - GDPR compliance for identity data protection

3. **Operational Excellence**
   - Clear service boundaries
   - Simplified troubleshooting
   - Scalable architecture
   - Reduced security monitoring surface

## Migration Notes

From the previous configuration with exposed LDAP ports to this secured setup:

- **Security Improvement**: LDAP ports no longer exposed to internet
- **Network Hardening**: Backend network fully internal
- **Zero Trust Enhancement**: Complete infrastructure isolation
- **No Functional Impact**: Dex continues to access LDAP via internal network

## Security Monitoring Recommendations

1. **Network Traffic Analysis**: Monitor inter-network communication patterns
2. **LDAP Access Logs**: Log all LDAP queries for anomaly detection
3. **Failed Authentication Monitoring**: Track authentication failures
4. **Network Boundary Alerts**: Alert on unexpected network access attempts

**Note:** All service communication now uses Docker DNS names (service names) instead of static IP addresses. This improves maintainability and flexibility.
