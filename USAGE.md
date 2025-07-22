# Flask LDAP-DEX OAuth2 Identity Provider - Usage Guide

## 🚀 Quick Start

```bash
# Start all services
docker compose up --build -d

# Check that all services are running
docker compose ps
```

## 🌐 Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **Protected Application** | http://localhost:5000 | Main OAuth2-protected Flask app |
| **Direct Backend** | http://localhost:8080 | Flask backend (protected by PEP) |
| **LDAP Server** | ldap://localhost:1389 | OpenLDAP directory service |
| **Dex OpenID Provider** | http://localhost:5556 | Direct Dex access (development) |
| **OpenID Discovery** | http://localhost/.well-known/openid-configuration | OIDC discovery endpoint |

## 🏗️ Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│ OAuth2 PEP  │────│ Apache      │
│             │    │ (port 5000) │    │ Proxy       │
└─────────────┘    └─────────────┘    │ (port 80)   │
                          │           └─────────────┘
                          │                  │
                          ▼                  ▼
                   ┌─────────────┐    ┌─────────────┐
                   │ Flask App   │    │ Dex OIDC    │
                   │ (port 8080) │    │ (port 5556) │
                   └─────────────┘    └─────────────┘
                                             │
                                             ▼
                                      ┌─────────────┐
                                      │ LDAP Server │
                                      │ (port 1389) │
                                      └─────────────┘
```

## ✅ Verification Tests

### 1. Test OpenID Connect Endpoints
```bash
# Test discovery endpoint
curl -s http://localhost/.well-known/openid-configuration | jq .issuer

# Test authorization endpoint (should return 302 redirect)
curl -I http://localhost/auth

# Test JWKS endpoint
curl -s http://localhost/keys | jq .keys[0].kty
```

### 2. Test OAuth2 Flow
```bash
# Initial access should redirect to login
curl -v http://localhost:5000/ 2>&1 | grep "Location:"

# Login endpoint should redirect to Dex
curl -v http://localhost:5000/oauth2/login 2>&1 | grep "Location:"
```

### 3. Test LDAP Server
```bash
# Verify LDAP users exist
docker exec ldap-server ldapsearch -x -H ldap://localhost \
  -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" \
  -w adminpassword "(objectClass=inetOrgPerson)" uid

# Test user authentication
docker exec ldap-server ldapsearch -x -H ldap://localhost \
  -b "dc=example,dc=org" -D "cn=user1,ou=people,dc=example,dc=org" \
  -w password1 "(uid=user1)"
```

### 4. Test Backend Protection
```bash
# Direct backend access should be forbidden
curl -I http://localhost:8080/
# Expected: HTTP/1.1 403 FORBIDDEN
```

## 👥 Available Users

### LDAP Users
| Username | Password | Email | Groups |
|----------|----------|-------|--------|
| user1 | password1 | user1@example.org | users |
| user2 | password2 | user2@example.org | users |
| user3 | password3 | user3@example.org | users |
| user4 | password4 | user4@example.org | users |

### Static Test User
| Username | Password | Email |
|----------|----------|-------|
| admin | admin | admin@example.com |

## 🔐 Complete Authentication Flow

1. **Access Application**: Navigate to http://localhost:5000
2. **OAuth2 Redirect**: Automatically redirected to `/oauth2/login`
3. **Dex Authorization**: Redirected to Dex login page via Apache proxy
4. **Choose Provider**: Select LDAP authentication or use static user
5. **LDAP Login**: Enter LDAP credentials (e.g., user1/password1)
6. **Token Exchange**: Dex issues OAuth2 tokens
7. **PEP Validation**: OAuth2 PEP validates tokens and extracts user info
8. **Protected Access**: Access granted to Flask backend with user headers

## 🛠️ Troubleshooting

### Services Won't Start
```bash
# Clean everything and restart
docker compose down -v
docker system prune -f
docker compose up --build -d
```

### LDAP Connection Issues
```bash
# Check LDAP logs
docker compose logs openldap

# Test LDAP connectivity
docker exec ldap-server ldapsearch -x -H ldap://localhost \
  -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" \
  -w adminpassword "(objectClass=*)"
```

### Dex Authentication Problems
```bash
# Check Dex logs
docker compose logs dex

# Verify Dex configuration
docker exec dex-server cat /etc/dex/config.yaml
```

### OAuth2 PEP Issues
```bash
# Check PEP logs
docker compose logs oauth2-pep

# Test PEP health
curl http://localhost:5000/health
```

### Apache Proxy Problems
```bash
# Check Apache logs
docker compose logs apache-proxy

# Test proxy endpoints
curl -I http://localhost/.well-known/openid-configuration
curl -I http://localhost/auth
```

### CSS/Static Resources Not Loading
```bash
# Test static resource access
curl -I http://localhost/static/main.css
curl -I http://localhost/theme/styles.css

# Should return HTTP/1.1 200 OK
```

## 📁 Project Structure

```
ldap-dex-IDP/
├── apache-proxy/        # Apache reverse proxy
│   ├── apache.conf      # Apache configuration
│   └── Dockerfile       # Apache container config
├── dex/                 # Dex OpenID Connect provider
│   ├── config.yaml      # Dex configuration with LDAP
│   ├── config-minimal.yaml # Minimal config (static users)
│   └── Dockerfile       # Dex container config
├── oauth2-pep/          # OAuth2 Policy Enforcement Point
│   ├── pep.py          # PEP application code
│   ├── requirements.txt # Python dependencies
│   └── Dockerfile      # PEP container config
├── flask-app/           # Protected Flask application
│   ├── app.py          # Flask backend application
│   ├── requirements.txt # Python dependencies
│   └── Dockerfile      # Flask container config
├── LDAP/               # OpenLDAP directory service
│   ├── bootstrap.ldif  # Initial LDAP data
│   ├── setup-users.sh  # User setup script
│   └── Dockerfile      # LDAP container config
├── docker-compose.yml  # Service orchestration
├── README.md          # Project documentation
├── USAGE.md           # This usage guide
└── validation-report.md # Test results and validation
```

## 🔧 Useful Commands

```bash
# View all logs
docker compose logs -f

# Restart specific service
docker compose restart <service-name>

# Enter container shell
docker exec -it <container-name> /bin/bash

# Check service health
docker compose ps
docker compose top

# Clean restart
docker compose down -v && docker compose up --build -d

# Test OAuth2 flow manually
curl -v http://localhost:5000/oauth2/login

# Test LDAP authentication
docker exec ldap-server ldapwhoami -x -D "cn=user1,ou=people,dc=example,dc=org" -w password1
```

## 🔍 Development Notes

### Configuration Files
- **Dex**: Uses `config.yaml` (with LDAP) by default
- **LDAP**: Bootstrapped with users from `bootstrap.ldif`
- **Apache**: Routes OpenID endpoints to Dex, includes static resources
- **PEP**: Handles OAuth2 flow and user session management

### Security Features
- ✅ OAuth2 Authorization Code flow
- ✅ LDAP authentication integration
- ✅ Backend protection via PEP
- ✅ Secure token validation
- ✅ User info injection via HTTP headers

### Network Configuration
- All services communicate via Docker internal network
- Only ports 80 and 5000 are exposed to host
- Internal service discovery via container names

## 📈 Performance Tips

- Use `docker compose up -d` for background operation
- Monitor logs with `docker compose logs -f`
- For production: use proper secrets management
- For load testing: scale OAuth2 PEP service

## 🎯 Next Steps

1. **Production Deployment**: 
   - Enable TLS/SSL encryption
   - Use external secrets management
   - Configure proper LDAP SSL certificates

2. **User Management**:
   - Add more LDAP users via LDIF files
   - Configure group-based authorization
   - Set up LDAP admin tools

3. **Monitoring**:
   - Add health checks for all services
   - Configure logging aggregation
   - Set up metrics collection 