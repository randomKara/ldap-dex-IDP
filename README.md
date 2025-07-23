# Flask OAuth2 PEP Identity Provider

A complete OAuth2 Policy Enforcement Point (PEP) architecture using Flask, OpenLDAP, and DEX for enterprise-grade authentication.

## Architecture

This application implements an OAuth2 PEP (Policy Enforcement Point) pattern with four main components:

- **OAuth2 PEP**: Policy Enforcement Point that handles authentication and proxies requests
- **Flask Backend**: Protected application that receives user info via HTTP headers
- **DEX Server**: OAuth2/OIDC Authorization Server that bridges to LDAP
- **OpenLDAP Server**: Identity backend with 4 test users

## Test Users

The LDAP server comes pre-configured with 4 test users:

| Username | Password | Email |
|----------|----------|-------|
| user1 | password1 | user1@example.org |
| user2 | password2 | user2@example.org |
| user3 | password3 | user3@example.org |
| user4 | password4 | user4@example.org |

## Quick Start

1. **Build and start all services:**
   ```bash
   docker compose up --build
   ```

2. **Access the application:**
   - Open your browser and go to: http://localhost:5000
   - Click "Login with DEX"
   - Use any of the test user credentials above
   - You should see "Hello *username*!" message

## Services

- **OAuth2 PEP**: http://localhost:5000 (main entry point)
- **Flask Backend**: http://localhost:8080 (protected, access via PEP only)
- **DEX OAuth2 Server**: http://localhost:5556 (authorization server)
- **LDAP Server**: ldap://localhost:1389 (identity backend)

## How It Works

1. User accesses application via OAuth2 PEP (port 5000)
2. PEP checks if user has valid OAuth2 session
3. If not authenticated, PEP redirects to DEX for OAuth2 authentication
4. DEX validates credentials against LDAP and returns authorization code
5. PEP exchanges code for access token and gets user info
6. PEP proxies request to Flask backend with user info in HTTP headers
7. Flask backend displays personalized welcome message

## OAuth2 Flow

```
User → OAuth2 PEP (5000) → DEX OAuth2 (5556) → LDAP (1389)
         ↓                    ↓
    Flask Backend (8080) ← User Info Headers
```

## Directory Structure

```
├── PEP/                # OAuth2 Policy Enforcement Point
├── flask-app/          # Protected Flask backend application  
├── dex/               # DEX OAuth2/OIDC Authorization Server
├── LDAP/              # OpenLDAP identity backend
└── docker-compose.yml # Orchestrates all services
```

## Configuration

- **LDAP Config**: `LDAP/bootstrap.ldif` contains user definitions
- **DEX Config**: `dex/config.yaml` configures OIDC and LDAP connection
- **Flask Config**: Environment variables in `docker-compose.yml`

## Development

To modify the application:

1. Make your changes to the relevant service directory
2. Rebuild the specific service:
   ```bash
   docker compose up --build <service-name>
   ```

## Troubleshooting

- Check service logs: `docker compose logs <service-name>`
- Verify LDAP connectivity: `docker compose logs openldap`
- Check DEX configuration: `docker compose logs dex`