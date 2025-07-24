# Multi-Network Architecture - Zero Trust Segmentation

## Architecture Overview

This project implements a **3-tier network segmentation** architecture following Zero Trust principles, isolating services by function and security level.

```
172.25.0.0/16 (Docker Global Network)
├── 172.25.0.0/24 (External/DMZ Network)
│   ├── 172.25.0.30 - Apache Reverse Proxy (Entry Point)
│   └── 172.25.0.40 - PEP (User Interface)
│
├── 172.25.1.0/24 (Backend/Infrastructure Network)
│   ├── 172.25.1.10 - OpenLDAP (Identity Store)
│   ├── 172.25.1.20 - Dex (OIDC Provider)
│   └── 172.25.1.30 - Apache Proxy (Backend Interface)
│
└── 172.25.2.0/24 (Application Network - ISOLATED)
    ├── 172.25.2.40 - PEP (App Interface)
    └── 172.25.2.50 - Flask Application (Business Logic)
```

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
- **Internet Access**: Limited (LDAP ports only)
- **Services**:
  - OpenLDAP (ports 1389, 1636 exposed for external access)
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
- ✅ **Controlled Access** to Backend services
- ✅ **DMZ Isolation** for public services
- ✅ **Multi-NIC Configuration** for cross-network communication

### Access Control
- 🛡️ **Principle of Least Privilege**: Services only access required networks
- 🛡️ **Defense in Depth**: Multiple security layers
- 🛡️ **Network Segmentation**: Compromise of one network doesn't affect others

### Communication Flow
```
User Request → External Network (PEP) → Application Network (Flask)
                ↓
Authentication → Backend Network (Dex) → Backend Network (LDAP)
```

## Service Communication Matrix

| From Service | To Service | Network Path | Purpose |
|--------------|------------|--------------|---------|
| **User** | PEP | External → External | Web Interface |
| **PEP** | Apache Proxy | External → External | OAuth2 Auth |
| **Apache Proxy** | Dex | External → Backend | OIDC Endpoints |
| **Dex** | LDAP | Backend → Backend | User Validation |
| **PEP** | Flask | External → Application | App Requests |

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
    internal: false  # LDAP needs external access
    ipam:
      config:
        - subnet: 172.25.1.0/24
          gateway: 172.25.1.1
    labels:
      - "purpose=backend"
      - "security.level=internal"

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
- **Service Communication**: Inter-network routing functional

### ✅ Security Validation
- **DMZ Protection**: Only authorized services exposed
- **Backend Isolation**: Infrastructure services protected
- **Application Isolation**: Flask completely isolated from internet

### ✅ Zero Trust Compliance
- **Never Trust, Always Verify**: Every network boundary protected
- **Least Privilege Access**: Minimal cross-network communication
- **Micro-segmentation**: Services isolated by function

## Benefits

1. **Enhanced Security Posture**
   - Reduced attack surface
   - Containment of security breaches
   - Defense in depth implementation

2. **Compliance Alignment**
   - ANSSI Zero Trust guidelines
   - Network segregation best practices
   - Audit trail through network boundaries

3. **Operational Excellence**
   - Clear service boundaries
   - Simplified troubleshooting
   - Scalable architecture

## Migration Notes

From the previous single-network (`172.25.0.0/24`) architecture to this multi-tier setup:

- **IP Changes**: All services reassigned to appropriate subnets
- **Security Improvement**: Application network isolation added
- **Zero Downtime**: Rolling deployment capability
- **Backward Compatibility**: External interfaces unchanged

---

*This architecture implements enterprise-grade network security while maintaining the functional OAuth2/OIDC authentication flow.* 