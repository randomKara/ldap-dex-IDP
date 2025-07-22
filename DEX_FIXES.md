# Dex OpenID Connect Fixes

## Problems Identified and Fixed

### 1. Issuer Configuration Mismatch
**Problem**: The issuer in Dex configuration was set to `http://localhost:5556`, but services access Dex through Apache proxy on port 80.

**Fix**: Updated both `config.yaml` and `config-minimal.yaml` to use `issuer: http://localhost` to match the public URL accessible via Apache proxy.

### 2. Docker Network Access Issues
**Problem**: The OAuth2 PEP container was trying to access `http://localhost` but couldn't reach the host from inside Docker.

**Fix**: Added `extra_hosts` configuration to the oauth2-pep service in docker-compose.yml:
```yaml
extra_hosts:
  - "localhost:host-gateway"
```

### 3. Docker Volume Mounting Inconsistency
**Problem**: The Dockerfile copies `config.yaml` but docker-compose was mounting `config-minimal.yaml`.

**Fix**: Updated docker-compose.yml to mount the correct configuration file:
```yaml
volumes:
  - ./dex/config.yaml:/etc/dex/config.yaml
```

### 4. Missing HTTP Headers
**Problem**: Apache proxy wasn't setting all necessary forwarded headers for Dex to understand the public URL.

**Fix**: Added `X-Forwarded-Host` header to Apache configuration:
```apache
Header always set X-Forwarded-Host "localhost"
```

## Architecture Overview

```
Browser → Apache Proxy (port 80) → Dex (internal port 5556)
                ↓
         OAuth2 PEP (port 5000) → Flask App (port 8080)
```

1. **Apache Proxy**: Routes OpenID endpoints (/.well-known, /auth, /token, /userinfo, /keys) to Dex
2. **Dex**: Provides OpenID Connect authentication with LDAP integration
3. **OAuth2 PEP**: Policy Enforcement Point that protects the Flask application
4. **Flask App**: Backend application protected by OAuth2

## Testing the Fixes

### 1. Build and Start Services
```bash
docker compose build
docker compose up -d
```

### 2. Check Service Health
```bash
docker compose ps
docker compose logs dex
docker compose logs apache-proxy
```

### 3. Test OpenID Endpoints
```bash
./test-dex-endpoints.sh
```

### 4. Test Full OAuth2 Flow
1. Open browser to `http://localhost:5000`
2. Should redirect to Dex login page
3. Login with LDAP credentials or static user (admin@example.com / admin)
4. Should redirect back to protected Flask application

## Expected Endpoint Responses

- **Discovery**: `GET http://localhost/.well-known/openid-configuration` → 200 + JSON
- **Authorization**: `GET http://localhost/auth` → 200 + HTML login page
- **Token**: `GET http://localhost/token` → 405 (POST only)
- **UserInfo**: `GET http://localhost/userinfo` → 401 (requires token)
- **JWKS**: `GET http://localhost/keys` → 200 + JSON

## Configuration Files Modified

1. `dex/config.yaml` - Updated issuer URL
2. `dex/config-minimal.yaml` - Updated issuer URL  
3. `docker-compose.yml` - Fixed volume mount and added extra_hosts
4. `apache-proxy/apache.conf` - Added X-Forwarded-Host header

## Troubleshooting

### If endpoints still return 404:
1. Check Apache proxy logs: `docker compose logs apache-proxy`
2. Verify Dex is running: `docker compose logs dex`
3. Test direct Dex access: `curl http://localhost:5556/.well-known/openid-configuration`

### If OAuth2 flow fails:
1. Check PEP logs: `docker compose logs oauth2-pep`
2. Verify callback URL matches in Dex config
3. Check network connectivity between containers

### If LDAP authentication fails:
1. Check LDAP server: `docker compose logs openldap`
2. Verify LDAP configuration in `dex/config.yaml`
3. Test LDAP connection manually 