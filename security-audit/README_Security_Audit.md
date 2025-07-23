# OAuth2/OIDC Zero Trust Security Audit Tool

## Overview

This comprehensive security audit tool validates OAuth2/OIDC Zero Trust architectures against industry standards and best practices. It performs automated security testing covering authentication flows, access controls, session management, and compliance verification.

## Features

### 🔒 **Security Testing Coverage**
- **Authentication Flow Validation**: OAuth2/OIDC flow integrity
- **Access Control Testing**: Zero Trust enforcement verification
- **Session Management**: Cookie security and session fixation protection
- **Input Validation**: SQL injection, XSS, and parameter manipulation
- **Network Security**: Port accessibility and service isolation
- **HTTPS/TLS Configuration**: Transport layer security validation
- **Security Headers**: HTTP security header compliance
- **Information Disclosure**: Sensitive data exposure prevention
- **Zero Trust Compliance**: Architecture principle validation

### 📊 **Reporting & Analytics**
- **Multiple Output Formats**: JSON and HTML reports
- **Executive Summaries**: High-level security posture assessment
- **Detailed Test Results**: Granular finding documentation
- **Zero Trust Scoring**: Quantitative compliance measurement
- **Remediation Recommendations**: Prioritized action items
- **Compliance Mapping**: Standards alignment verification

### ⚙️ **Enterprise Features**
- **Configurable Testing**: YAML-based configuration management
- **Extensible Architecture**: Custom test integration support
- **Performance Monitoring**: Response time and availability tracking
- **Automated Scheduling**: Continuous security validation
- **Integration Ready**: CI/CD pipeline compatibility
- **Audit Logging**: Comprehensive activity tracking

## Installation

### Prerequisites
- Python 3.8 or higher
- Network access to target services
- Appropriate permissions for security testing

### Quick Installation
```bash
# Clone or download the security audit tool
git clone <repository-url>
cd oauth2-oidc-security-audit

# Install dependencies
pip install -r requirements.txt

# Create default configuration
python security_audit.py --create-config

# Run basic audit
python security_audit.py
```

### Docker Installation
```bash
# Build Docker image
docker build -t oauth2-security-audit .

# Run containerized audit
docker run --network host -v $(pwd):/reports oauth2-security-audit
```

## Configuration

### Basic Configuration
Edit `security_audit_config.yaml` to match your environment:

```yaml
targets:
  pep_endpoint: "http://localhost:5000"
  oidc_provider: "http://localhost:5556" 
  backend_app: "http://localhost:8080"
  https_endpoint: "https://localhost:5443"

authentication:
  client_id: "your-client-id"
  redirect_uri: "http://localhost:5000/oauth2callback"
  scopes: ["openid", "email", "profile", "groups"]
```

### Advanced Configuration
```yaml
security_tests:
  timeout: 10
  max_retries: 3
  rate_limit_requests: 20
  
compliance:
  required_headers:
    - "X-Content-Type-Options"
    - "X-Frame-Options"
    - "Strict-Transport-Security"
    
zero_trust:
  min_auth_coverage: 90
  max_direct_access: 0
```

## Usage

### Basic Security Audit
```bash
# Run complete security audit
python security_audit.py

# Use custom configuration
python security_audit.py --config custom_config.yaml

# Enable verbose logging
python security_audit.py --verbose
```

### Targeted Testing
```bash
# Test specific categories
python security_audit.py --categories "Authentication Flow,Access Control"

# Skip non-critical tests
python security_audit.py --severity "HIGH,CRITICAL"

# Generate only JSON report
python security_audit.py --format json
```

### CI/CD Integration
```bash
# Exit with non-zero code on security issues
python security_audit.py --fail-on "HIGH,CRITICAL"

# Generate machine-readable output
python security_audit.py --format json --output security_results.json
```

## Test Categories

### 1. Infrastructure Testing
- **Service Availability**: Endpoint connectivity validation
- **Port Accessibility**: Network service exposure assessment
- **Service Dependencies**: Component interaction verification

### 2. Authentication Flow Testing
- **OIDC Discovery**: Provider metadata validation
- **Authorization Flow**: OAuth2 flow integrity check
- **Token Validation**: JWT token structure and claims
- **Redirect Validation**: URI whitelist enforcement

### 3. Access Control Testing
- **Zero Trust Enforcement**: Authentication requirement validation
- **Direct Access Prevention**: Backend service isolation
- **Header Injection**: Malicious header bypass attempts
- **Session Fixation**: Session security validation

### 4. Session Management Testing
- **Cookie Security**: HTTPOnly, Secure, SameSite flags
- **Session Timeout**: Automatic session expiration
- **Session Regeneration**: Login session renewal
- **Cross-Site Request Forgery**: CSRF protection validation

### 5. Input Validation Testing
- **SQL Injection**: Database query manipulation attempts
- **Cross-Site Scripting**: HTML/JavaScript injection testing
- **Parameter Pollution**: HTTP parameter manipulation
- **Path Traversal**: Directory traversal attack prevention

### 6. Network Security Testing
- **Port Enumeration**: Exposed service identification
- **Service Isolation**: Network segmentation validation
- **Protocol Security**: Secure communication enforcement
- **DNS Security**: Domain name resolution validation

### 7. HTTPS/TLS Testing
- **Certificate Validation**: SSL/TLS certificate verification
- **Protocol Version**: Secure protocol enforcement
- **Cipher Suite**: Strong encryption validation
- **HTTP Redirection**: Secure transport enforcement

### 8. Security Headers Testing
- **Content Security Policy**: XSS protection headers
- **Transport Security**: HSTS header validation
- **Frame Options**: Clickjacking protection
- **Content Type**: MIME type sniffing prevention

### 9. Information Disclosure Testing
- **Error Messages**: Sensitive data exposure in errors
- **Debug Information**: Development artifact exposure
- **Server Fingerprinting**: Technology stack disclosure
- **Directory Listing**: File system exposure

### 10. Zero Trust Compliance Testing
- **Never Trust, Always Verify**: Authentication enforcement
- **Least Privilege Access**: Minimal permission assignment
- **Micro-Segmentation**: Network isolation validation
- **Continuous Monitoring**: Security posture assessment

## Report Interpretation

### Zero Trust Score
The Zero Trust Score (0-100) quantifies compliance with Zero Trust principles:
- **90-100**: Excellent Zero Trust implementation
- **80-89**: Good with minor improvements needed
- **70-79**: Adequate but requires attention
- **60-69**: Poor with significant gaps
- **Below 60**: Critical security deficiencies

### Security Posture Levels
- **LOW_RISK**: Minimal security issues, acceptable posture
- **MEDIUM_RISK**: Some issues present, monitoring recommended
- **HIGH_RISK**: Significant vulnerabilities, immediate action required
- **CRITICAL**: Severe security gaps, emergency response needed

### Severity Classifications
- **CRITICAL**: Immediate security threat, exploitable vulnerability
- **HIGH**: Significant risk, should be addressed urgently
- **MEDIUM**: Moderate risk, address in next maintenance window
- **LOW**: Minor security improvement opportunity
- **INFO**: Informational finding, no immediate action required

## Sample Reports

### JSON Report Structure
```json
{
  "summary": {
    "audit_timestamp": "2024-01-15T10:30:00Z",
    "total_tests": 45,
    "passed_tests": 38,
    "failed_tests": 7,
    "success_rate": 84.4,
    "zero_trust_score": 87,
    "overall_security_posture": "MEDIUM_RISK"
  },
  "test_results": {
    "Authentication Flow": [...],
    "Access Control": [...],
    "Session Management": [...]
  },
  "recommendations": [
    "Add Strict-Transport-Security header",
    "Implement Content Security Policy",
    "Enable HTTP to HTTPS redirect"
  ],
  "compliance_status": {
    "OAuth2_Security_BCP": "COMPLIANT",
    "Zero_Trust_Architecture": "NON_COMPLIANT"
  }
}
```

### HTML Report Features
- **Executive Summary Dashboard**: Key metrics and trends
- **Interactive Test Results**: Expandable sections by category
- **Visual Severity Indicators**: Color-coded risk levels
- **Remediation Roadmap**: Prioritized action items
- **Compliance Matrix**: Standards alignment status

## Best Practices

### Pre-Audit Preparation
1. **Environment Setup**: Ensure all services are running
2. **Network Access**: Verify connectivity to target endpoints
3. **Permission Validation**: Confirm testing authorization
4. **Baseline Documentation**: Record current configuration

### During Audit Execution
1. **Monitor Performance**: Watch for service impact
2. **Log Analysis**: Review real-time security logs
3. **Network Monitoring**: Observe traffic patterns
4. **Error Handling**: Document any test failures

### Post-Audit Actions
1. **Review Findings**: Analyze all security issues
2. **Prioritize Remediation**: Address critical issues first
3. **Plan Implementation**: Schedule security improvements
4. **Validate Fixes**: Re-run tests after remediation

## Troubleshooting

### Common Issues

#### Connection Timeouts
```bash
# Increase timeout values
python security_audit.py --config config_high_timeout.yaml
```

#### Certificate Errors
```bash
# Disable SSL verification for testing
export PYTHONHTTPSVERIFY=0
python security_audit.py
```

#### Permission Denied
```bash
# Run with appropriate permissions
sudo python security_audit.py
```

### Debugging
```bash
# Enable debug logging
python security_audit.py --verbose

# Check audit log
tail -f security_audit.log

# Validate configuration
python security_audit.py --validate-config
```

## Compliance Standards

This tool validates compliance with:
- **OAuth 2.0 Security Best Practices (RFC 6749)**
- **OpenID Connect Core 1.0 Specification**
- **NIST Zero Trust Architecture (SP 800-207)**
- **OWASP Top 10 Web Application Security Risks**
- **CIS Controls for Effective Cyber Defense**
- **ISO/IEC 27001 Information Security Management**

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd oauth2-oidc-security-audit

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black security_audit.py

# Linting
flake8 security_audit.py
```

### Adding Custom Tests
1. Create test class inheriting from `SecurityTestResult`
2. Implement test logic following existing patterns
3. Add test to appropriate category
4. Update documentation

### Reporting Issues
1. Use GitHub Issues for bug reports
2. Include configuration and error logs
3. Provide steps to reproduce
4. Specify environment details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [Wiki](wiki-url)
- **Issues**: [GitHub Issues](issues-url) 
- **Discussions**: [GitHub Discussions](discussions-url)
- **Security**: [Security Policy](security-url)

## Changelog

### Version 1.0.0
- Initial release with comprehensive OAuth2/OIDC testing
- Zero Trust architecture validation
- Multi-format reporting (JSON/HTML)
- Configurable test scenarios
- Enterprise-grade features

---

**⚠️ Security Notice**: This tool is designed for authorized security testing only. Ensure you have proper permission before running against production systems. 