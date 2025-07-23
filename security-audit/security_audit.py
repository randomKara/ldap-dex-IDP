#!/usr/bin/env python3
"""
OAuth2/OIDC Zero Trust Security Audit Tool

This tool performs comprehensive security testing of OAuth2/OIDC Zero Trust architectures.
It validates authentication flows, access controls, and security posture.

Author: Security Team
Version: 1.0.0
License: MIT
"""

import json
import logging
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import argparse
import sys

try:
    import requests
    import yaml
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Install with: pip install requests pyyaml")
    sys.exit(1)


class SecurityAuditConfig:
    """Configuration management for security audit."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_default_config()
        if config_file and Path(config_file).exists():
            self._load_config_file(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            "targets": {
                "pep_endpoint": "http://localhost:5000",
                "oidc_provider": "http://localhost:5556",
                "backend_app": "http://localhost:8080",
                "ldap_port": 1389,
                "https_endpoint": "https://localhost:5443"
            },
            "authentication": {
                "client_id": "flask-app",
                "redirect_uri": "http://localhost:5000/oauth2callback",
                "scopes": ["openid", "email", "profile", "groups"]
            },
            "security_tests": {
                "timeout": 10,
                "max_retries": 3,
                "rate_limit_requests": 20,
                "payload_sizes": [1024, 10240, 102400],
                "sql_injection_payloads": [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "1' UNION SELECT password FROM users--"
                ],
                "xss_payloads": [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>"
                ]
            },
            "compliance": {
                "required_headers": [
                    "X-Content-Type-Options",
                    "X-Frame-Options", 
                    "X-XSS-Protection",
                    "Strict-Transport-Security"
                ],
                "forbidden_headers": [
                    "Server",
                    "X-Powered-By"
                ]
            },
            "reporting": {
                "output_format": ["json", "html"],
                "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                "include_recommendations": True
            }
        }
    
    def _load_config_file(self, config_file: str) -> None:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                self._deep_update(self.config, user_config)
        except Exception as e:
            logging.warning(f"Failed to load config file {config_file}: {e}")
    
    def _deep_update(self, base_dict: Dict, update_dict: Dict) -> None:
        """Deep update dictionary."""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict:
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value


class SecurityTestResult:
    """Container for security test results."""
    
    def __init__(self, test_name: str, category: str):
        self.test_name = test_name
        self.category = category
        self.passed = False
        self.severity = "INFO"
        self.details = ""
        self.recommendations = []
        self.evidence = {}
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "test_name": self.test_name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "details": self.details,
            "recommendations": self.recommendations,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }


class HTTPClient:
    """Enhanced HTTP client with retry logic and security features."""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.session = requests.Session()
        self.timeout = timeout
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Disable SSL warnings for testing
        requests.packages.urllib3.disable_warnings()
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with enhanced error handling."""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)  # For testing self-signed certs
        kwargs.setdefault('allow_redirects', False)
        
        try:
            response = self.session.request(method, url, **kwargs)
            logging.debug(f"{method} {url} -> {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {method} {url} - {e}")
            # Return mock response for failed requests
            mock_response = requests.Response()
            mock_response.status_code = 0
            mock_response._content = b""
            return mock_response


class ZeroTrustSecurityAuditor:
    """Main security auditor class."""
    
    def __init__(self, config: SecurityAuditConfig):
        self.config = config.config
        self.http_client = HTTPClient(
            timeout=self.config["security_tests"]["timeout"],
            max_retries=self.config["security_tests"]["max_retries"]
        )
        self.results: List[SecurityTestResult] = []
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_audit.log'),
                logging.StreamHandler()
            ]
        )
    
    def run_full_audit(self) -> Dict[str, Any]:
        """Run complete security audit."""
        logging.info("Starting OAuth2/OIDC Zero Trust Security Audit")
        start_time = time.time()
        
        # Test categories
        test_categories = [
            ("Infrastructure", self._test_infrastructure),
            ("Authentication Flow", self._test_authentication_flow),
            ("Access Control", self._test_access_control),
            ("Session Management", self._test_session_management),
            ("Input Validation", self._test_input_validation),
            ("Network Security", self._test_network_security),
            ("HTTPS/TLS", self._test_https_tls),
            ("Security Headers", self._test_security_headers),
            ("Information Disclosure", self._test_information_disclosure),
            ("Zero Trust Compliance", self._test_zero_trust_compliance)
        ]
        
        for category, test_method in test_categories:
            logging.info(f"Running {category} tests...")
            try:
                test_method()
            except Exception as e:
                logging.error(f"Failed to run {category} tests: {e}")
                self._add_result(
                    f"{category}_execution_error",
                    category,
                    False,
                    "CRITICAL",
                    f"Test execution failed: {e}"
                )
        
        execution_time = time.time() - start_time
        return self._generate_report(execution_time)
    
    def _test_infrastructure(self) -> None:
        """Test infrastructure availability and basic connectivity."""
        endpoints = [
            ("PEP Endpoint", self.config["targets"]["pep_endpoint"]),
            ("OIDC Provider", self.config["targets"]["oidc_provider"]),
            ("Backend Application", self.config["targets"]["backend_app"])
        ]
        
        for name, url in endpoints:
            result = self._create_result(f"infrastructure_{name.lower().replace(' ', '_')}", "Infrastructure")
            
            try:
                response = self.http_client.request("GET", url)
                if response.status_code > 0:
                    result.passed = True
                    result.details = f"{name} is accessible (HTTP {response.status_code})"
                    result.evidence = {"status_code": response.status_code, "url": url}
                else:
                    result.details = f"{name} is not accessible"
                    result.severity = "HIGH"
                    result.recommendations.append(f"Ensure {name} is running and accessible")
            except Exception as e:
                result.details = f"{name} connectivity failed: {e}"
                result.severity = "CRITICAL"
            
            self.results.append(result)
    
    def _test_authentication_flow(self) -> None:
        """Test OAuth2/OIDC authentication flow."""
        pep_url = self.config["targets"]["pep_endpoint"]
        
        # Test 1: Unauthenticated access should redirect
        result = self._create_result("auth_unauthenticated_redirect", "Authentication Flow")
        response = self.http_client.request("GET", pep_url)
        
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if 'auth' in location and 'client_id' in location:
                result.passed = True
                result.details = "Unauthenticated requests properly redirected to OIDC provider"
                result.evidence = {"location": location, "status_code": 302}
            else:
                result.details = f"Redirect location suspicious: {location}"
                result.severity = "MEDIUM"
        else:
            result.details = f"Expected 302 redirect, got {response.status_code}"
            result.severity = "HIGH"
            result.recommendations.append("Ensure all unauthenticated requests redirect to OIDC provider")
        
        self.results.append(result)
        
        # Test 2: OIDC Discovery
        result = self._create_result("oidc_discovery", "Authentication Flow")
        discovery_url = f"{self.config['targets']['oidc_provider']}/.well-known/openid-configuration"
        response = self.http_client.request("GET", discovery_url)
        
        if response.status_code == 200:
            try:
                discovery_data = response.json()
                required_fields = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']
                missing_fields = [field for field in required_fields if field not in discovery_data]
                
                if not missing_fields:
                    result.passed = True
                    result.details = "OIDC discovery endpoint properly configured"
                    result.evidence = discovery_data
                else:
                    result.details = f"OIDC discovery missing required fields: {missing_fields}"
                    result.severity = "HIGH"
            except json.JSONDecodeError:
                result.details = "OIDC discovery endpoint returned invalid JSON"
                result.severity = "HIGH"
        else:
            result.details = f"OIDC discovery endpoint failed: HTTP {response.status_code}"
            result.severity = "HIGH"
        
        self.results.append(result)
    
    def _test_access_control(self) -> None:
        """Test access control mechanisms."""
        # Test 1: Direct backend access should be blocked
        result = self._create_result("access_control_backend_direct", "Access Control")
        backend_url = self.config["targets"]["backend_app"]
        response = self.http_client.request("GET", backend_url)
        
        if response.status_code in [403, 401, 302]:
            result.passed = True
            result.details = f"Direct backend access properly blocked (HTTP {response.status_code})"
            result.evidence = {"status_code": response.status_code}
        else:
            result.details = f"Backend directly accessible: HTTP {response.status_code}"
            result.severity = "CRITICAL"
            result.recommendations.append("Block direct access to backend applications")
        
        self.results.append(result)
        
        # Test 2: Header injection bypass attempts
        malicious_headers = [
            {"X-User-ID": "admin", "X-Authenticated": "true"},
            {"Authorization": "Bearer fake-token"},
            {"X-Forwarded-User": "admin"},
            {"Remote-User": "admin"}
        ]
        
        for i, headers in enumerate(malicious_headers):
            result = self._create_result(f"access_control_header_injection_{i+1}", "Access Control")
            pep_url = self.config["targets"]["pep_endpoint"]
            response = self.http_client.request("GET", pep_url, headers=headers)
            
            if response.status_code == 302:
                result.passed = True
                result.details = f"Header injection attempt blocked: {headers}"
                result.evidence = {"headers": headers, "status_code": response.status_code}
            else:
                result.details = f"Header injection may have succeeded: {headers}"
                result.severity = "CRITICAL"
                result.recommendations.append("Implement header sanitization and validation")
            
            self.results.append(result)
    
    def _test_session_management(self) -> None:
        """Test session management security."""
        pep_url = self.config["targets"]["pep_endpoint"]
        
        # Test 1: Cookie security attributes
        result = self._create_result("session_cookie_security", "Session Management")
        response = self.http_client.request("GET", pep_url)
        
        set_cookie = response.headers.get('Set-Cookie', '')
        security_flags = ['HttpOnly', 'Secure', 'SameSite']
        present_flags = [flag for flag in security_flags if flag in set_cookie]
        
        if len(present_flags) >= 2:  # At least HttpOnly and SameSite
            result.passed = True
            result.details = f"Session cookies have security flags: {present_flags}"
            result.evidence = {"set_cookie": set_cookie, "security_flags": present_flags}
        else:
            result.details = f"Session cookies missing security flags. Present: {present_flags}"
            result.severity = "MEDIUM"
            result.recommendations.append("Add HttpOnly, Secure, and SameSite flags to session cookies")
        
        self.results.append(result)
        
        # Test 2: Session fixation protection
        result = self._create_result("session_fixation_protection", "Session Management")
        fake_cookies = {"mod_auth_openidc_session": "malicious-session-id"}
        response = self.http_client.request("GET", pep_url, cookies=fake_cookies)
        
        if response.status_code == 302:
            result.passed = True
            result.details = "Fake session cookies rejected"
            result.evidence = {"status_code": response.status_code}
        else:
            result.details = "Session fixation may be possible"
            result.severity = "HIGH"
            result.recommendations.append("Implement session validation and regeneration")
        
        self.results.append(result)
    
    def _test_input_validation(self) -> None:
        """Test input validation and injection protection."""
        pep_url = self.config["targets"]["pep_endpoint"]
        
        # Test SQL injection in callback
        for i, payload in enumerate(self.config["security_tests"]["sql_injection_payloads"]):
            result = self._create_result(f"input_validation_sql_injection_{i+1}", "Input Validation")
            callback_url = f"{pep_url}/oauth2callback?code={urllib.parse.quote(payload)}&state=test"
            response = self.http_client.request("GET", callback_url)
            
            if response.status_code in [400, 401, 403]:
                result.passed = True
                result.details = f"SQL injection payload rejected: {payload}"
                result.evidence = {"payload": payload, "status_code": response.status_code}
            else:
                result.details = f"Potential SQL injection vulnerability: {payload}"
                result.severity = "HIGH"
                result.recommendations.append("Implement input sanitization and parameterized queries")
            
            self.results.append(result)
        
        # Test XSS in parameters
        for i, payload in enumerate(self.config["security_tests"]["xss_payloads"]):
            result = self._create_result(f"input_validation_xss_{i+1}", "Input Validation")
            test_url = f"{pep_url}?test={urllib.parse.quote(payload)}"
            response = self.http_client.request("GET", test_url)
            
            if payload not in response.text:
                result.passed = True
                result.details = f"XSS payload properly escaped: {payload}"
            else:
                result.details = f"Potential XSS vulnerability: {payload}"
                result.severity = "HIGH"
                result.recommendations.append("Implement output encoding and CSP headers")
            
            self.results.append(result)
    
    def _test_network_security(self) -> None:
        """Test network-level security."""
        # Test port accessibility
        import socket
        
        ports_to_test = [
            (self.config["targets"]["ldap_port"], "LDAP", False),
            (5556, "OIDC Provider", True),
            (8080, "Backend App", False)
        ]
        
        for port, service, should_be_accessible in ports_to_test:
            result = self._create_result(f"network_port_accessibility_{port}", "Network Security")
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result_code = sock.connect_ex(('localhost', port))
                sock.close()
                
                is_accessible = result_code == 0
                
                if is_accessible == should_be_accessible:
                    result.passed = True
                    result.details = f"{service} port {port} accessibility is correct"
                else:
                    result.details = f"{service} port {port} accessibility issue"
                    result.severity = "MEDIUM" if should_be_accessible else "HIGH"
                    
                result.evidence = {"port": port, "accessible": is_accessible, "expected": should_be_accessible}
                
            except Exception as e:
                result.details = f"Network test failed for port {port}: {e}"
                result.severity = "LOW"
            
            self.results.append(result)
    
    def _test_https_tls(self) -> None:
        """Test HTTPS/TLS configuration."""
        https_url = self.config["targets"]["https_endpoint"]
        
        # Test 1: HTTPS availability
        result = self._create_result("https_availability", "HTTPS/TLS")
        
        try:
            response = self.http_client.request("GET", https_url)
            if response.status_code > 0:
                result.passed = True
                result.details = "HTTPS endpoint is accessible"
                result.evidence = {"status_code": response.status_code}
            else:
                result.details = "HTTPS endpoint not available"
                result.severity = "HIGH"
                result.recommendations.append("Implement HTTPS with proper TLS configuration")
        except Exception as e:
            result.details = f"HTTPS not configured: {e}"
            result.severity = "HIGH"
            result.recommendations.append("Configure HTTPS/TLS for all endpoints")
        
        self.results.append(result)
        
        # Test 2: HTTP to HTTPS redirect
        result = self._create_result("http_to_https_redirect", "HTTPS/TLS")
        http_url = self.config["targets"]["pep_endpoint"]
        
        try:
            response = self.http_client.request("GET", http_url)
            if response.status_code == 301 and 'https' in response.headers.get('Location', ''):
                result.passed = True
                result.details = "HTTP properly redirects to HTTPS"
            else:
                result.details = "HTTP does not redirect to HTTPS"
                result.severity = "MEDIUM"
                result.recommendations.append("Configure HTTP to HTTPS redirect")
        except Exception as e:
            result.details = f"Redirect test failed: {e}"
            result.severity = "LOW"
        
        self.results.append(result)
    
    def _test_security_headers(self) -> None:
        """Test security headers."""
        pep_url = self.config["targets"]["pep_endpoint"]
        response = self.http_client.request("GET", pep_url)
        
        # Test required security headers
        for header in self.config["compliance"]["required_headers"]:
            result = self._create_result(f"security_header_{header.lower().replace('-', '_')}", "Security Headers")
            
            if header in response.headers:
                result.passed = True
                result.details = f"Security header {header} is present: {response.headers[header]}"
                result.evidence = {header: response.headers[header]}
            else:
                result.details = f"Missing security header: {header}"
                result.severity = "MEDIUM"
                result.recommendations.append(f"Add {header} security header")
            
            self.results.append(result)
        
        # Test forbidden headers (information disclosure)
        for header in self.config["compliance"]["forbidden_headers"]:
            result = self._create_result(f"info_disclosure_{header.lower().replace('-', '_')}", "Security Headers")
            
            if header not in response.headers:
                result.passed = True
                result.details = f"Information disclosure header {header} is properly hidden"
            else:
                result.details = f"Information disclosure via {header}: {response.headers[header]}"
                result.severity = "LOW"
                result.recommendations.append(f"Remove or mask {header} header")
            
            self.results.append(result)
    
    def _test_information_disclosure(self) -> None:
        """Test for information disclosure vulnerabilities."""
        base_url = self.config["targets"]["pep_endpoint"]
        
        # Test access to sensitive files
        sensitive_paths = [
            "/.env",
            "/config.yaml", 
            "/.htaccess",
            "/server-status",
            "/server-info",
            "/admin",
            "/actuator/health"
        ]
        
        for path in sensitive_paths:
            result = self._create_result(f"info_disclosure_path_{path.replace('/', '_').replace('.', '_')}", "Information Disclosure")
            url = f"{base_url}{path}"
            response = self.http_client.request("GET", url)
            
            if response.status_code in [404, 403, 302]:
                result.passed = True
                result.details = f"Sensitive path {path} is properly protected"
                result.evidence = {"path": path, "status_code": response.status_code}
            else:
                result.details = f"Sensitive path {path} may be accessible"
                result.severity = "MEDIUM"
                result.recommendations.append(f"Block access to {path}")
            
            self.results.append(result)
    
    def _test_zero_trust_compliance(self) -> None:
        """Test Zero Trust architecture compliance."""
        # Test 1: Never trust, always verify
        result = self._create_result("zero_trust_never_trust", "Zero Trust Compliance")
        
        # Count how many tests require authentication
        auth_required_tests = [r for r in self.results if 'redirect' in r.details.lower() or r.test_name.startswith('access_control')]
        total_access_tests = len([r for r in self.results if 'access' in r.category.lower()])
        
        if total_access_tests > 0 and len(auth_required_tests) / total_access_tests > 0.8:
            result.passed = True
            result.details = "Strong authentication enforcement across endpoints"
            result.evidence = {"auth_tests": len(auth_required_tests), "total_tests": total_access_tests}
        else:
            result.details = "Weak authentication enforcement detected"
            result.severity = "HIGH"
            result.recommendations.append("Ensure all resources require authentication")
        
        self.results.append(result)
        
        # Test 2: Least privilege access
        result = self._create_result("zero_trust_least_privilege", "Zero Trust Compliance")
        
        # Check if direct backend access is blocked
        backend_blocked = any(
            r.passed and 'backend' in r.test_name and 'blocked' in r.details.lower() 
            for r in self.results
        )
        
        if backend_blocked:
            result.passed = True
            result.details = "Least privilege enforced - backend not directly accessible"
        else:
            result.details = "Least privilege violation - direct backend access possible"
            result.severity = "CRITICAL"
            result.recommendations.append("Implement network segmentation and access controls")
        
        self.results.append(result)
    
    def _create_result(self, test_name: str, category: str) -> SecurityTestResult:
        """Create a new security test result."""
        return SecurityTestResult(test_name, category)
    
    def _add_result(self, test_name: str, category: str, passed: bool, severity: str, details: str) -> None:
        """Add a test result."""
        result = self._create_result(test_name, category)
        result.passed = passed
        result.severity = severity
        result.details = details
        self.results.append(result)
    
    def _generate_report(self, execution_time: float) -> Dict[str, Any]:
        """Generate comprehensive security audit report."""
        total_tests = len(self.results)
        passed_tests = len([r for r in self.results if r.passed])
        failed_tests = total_tests - passed_tests
        
        # Categorize results by severity
        severity_counts = {}
        for severity in self.config["reporting"]["severity_levels"]:
            severity_counts[severity] = len([r for r in self.results if r.severity == severity and not r.passed])
        
        # Generate summary
        summary = {
            "audit_timestamp": datetime.now().isoformat(),
            "execution_time_seconds": round(execution_time, 2),
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": round((passed_tests / total_tests * 100), 2) if total_tests > 0 else 0,
            "severity_breakdown": severity_counts,
            "zero_trust_score": self._calculate_zero_trust_score(),
            "overall_security_posture": self._assess_security_posture(severity_counts)
        }
        
        # Group results by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result.to_dict())
        
        report = {
            "summary": summary,
            "test_results": categories,
            "recommendations": self._generate_recommendations(),
            "compliance_status": self._assess_compliance()
        }
        
        # Save reports
        self._save_json_report(report)
        if "html" in self.config["reporting"]["output_format"]:
            self._save_html_report(report)
        
        return report
    
    def _calculate_zero_trust_score(self) -> int:
        """Calculate Zero Trust compliance score (0-100)."""
        if not self.results:
            return 0
        
        # Weight different categories
        category_weights = {
            "Access Control": 0.25,
            "Authentication Flow": 0.20,
            "Session Management": 0.15,
            "Network Security": 0.15,
            "HTTPS/TLS": 0.10,
            "Security Headers": 0.10,
            "Zero Trust Compliance": 0.05
        }
        
        total_score = 0
        total_weight = 0
        
        for category, weight in category_weights.items():
            category_results = [r for r in self.results if r.category == category]
            if category_results:
                category_score = len([r for r in category_results if r.passed]) / len(category_results)
                total_score += category_score * weight
                total_weight += weight
        
        return int((total_score / total_weight * 100)) if total_weight > 0 else 0
    
    def _assess_security_posture(self, severity_counts: Dict[str, int]) -> str:
        """Assess overall security posture."""
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 2:
            return "HIGH_RISK"
        elif severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) > 5:
            return "MEDIUM_RISK"
        else:
            return "LOW_RISK"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        all_recommendations = []
        for result in self.results:
            if not result.passed and result.recommendations:
                all_recommendations.extend(result.recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in all_recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Top 10 recommendations
    
    def _assess_compliance(self) -> Dict[str, str]:
        """Assess compliance with security standards."""
        compliance_results = {}
        
        # OAuth 2.0 Security Best Practices
        oauth_tests = [r for r in self.results if "auth" in r.category.lower()]
        oauth_score = len([r for r in oauth_tests if r.passed]) / len(oauth_tests) if oauth_tests else 0
        compliance_results["OAuth2_Security_BCP"] = "COMPLIANT" if oauth_score > 0.8 else "NON_COMPLIANT"
        
        # Zero Trust Architecture
        zt_tests = [r for r in self.results if "zero trust" in r.category.lower() or "access control" in r.category.lower()]
        zt_score = len([r for r in zt_tests if r.passed]) / len(zt_tests) if zt_tests else 0
        compliance_results["Zero_Trust_Architecture"] = "COMPLIANT" if zt_score > 0.9 else "NON_COMPLIANT"
        
        return compliance_results
    
    def _save_json_report(self, report: Dict[str, Any]) -> None:
        """Save JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_audit_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"JSON report saved: {filename}")
    
    def _save_html_report(self, report: Dict[str, Any]) -> None:
        """Save HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_audit_report_{timestamp}.html"
        
        html_content = self._generate_html_report(report)
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        logging.info(f"HTML report saved: {filename}")
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report."""
        summary = report["summary"]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth2/OIDC Zero Trust Security Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .category {{ margin: 20px 0; }}
                .test-result {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
                .passed {{ border-color: #27ae60; background: #d5f4e6; }}
                .failed {{ border-color: #e74c3c; background: #fdf2f2; }}
                .critical {{ border-color: #8e44ad; background: #f8f4fd; }}
                .recommendations {{ background: #fff3cd; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>OAuth2/OIDC Zero Trust Security Audit Report</h1>
                <p>Generated: {summary['audit_timestamp']}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Tests:</strong> {summary['total_tests']}</p>
                <p><strong>Success Rate:</strong> {summary['success_rate']}%</p>
                <p><strong>Zero Trust Score:</strong> {summary['zero_trust_score']}/100</p>
                <p><strong>Security Posture:</strong> {summary['overall_security_posture']}</p>
                <p><strong>Execution Time:</strong> {summary['execution_time_seconds']} seconds</p>
            </div>
        """
        
        # Add test results by category
        for category, tests in report["test_results"].items():
            html += f'<div class="category"><h3>{category}</h3>'
            for test in tests:
                status_class = "passed" if test["passed"] else "failed"
                if test["severity"] == "CRITICAL":
                    status_class = "critical"
                
                html += f'''
                <div class="test-result {status_class}">
                    <strong>{test["test_name"]}</strong><br>
                    {test["details"]}<br>
                    <small>Severity: {test["severity"]}</small>
                </div>
                '''
            html += '</div>'
        
        # Add recommendations
        if report["recommendations"]:
            html += '<div class="recommendations"><h3>Top Recommendations</h3><ul>'
            for rec in report["recommendations"]:
                html += f'<li>{rec}</li>'
            html += '</ul></div>'
        
        html += '</body></html>'
        return html


def create_default_config():
    """Create default configuration file."""
    config = SecurityAuditConfig()
    
    with open('security_audit_config.yaml', 'w') as f:
        yaml.dump(config.config, f, default_flow_style=False, indent=2)
    
    print("Default configuration created: security_audit_config.yaml")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="OAuth2/OIDC Zero Trust Security Audit Tool")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--create-config", action="store_true", help="Create default configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.create_config:
        create_default_config()
        return
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = SecurityAuditConfig(args.config)
    
    # Run audit
    auditor = ZeroTrustSecurityAuditor(config)
    report = auditor.run_full_audit()
    
    # Print summary
    summary = report["summary"]
    print(f"\n{'='*60}")
    print("OAUTH2/OIDC ZERO TRUST SECURITY AUDIT COMPLETE")
    print(f"{'='*60}")
    print(f"Tests Run: {summary['total_tests']}")
    print(f"Success Rate: {summary['success_rate']}%")
    print(f"Zero Trust Score: {summary['zero_trust_score']}/100")
    print(f"Security Posture: {summary['overall_security_posture']}")
    print(f"Execution Time: {summary['execution_time_seconds']} seconds")
    
    if summary['overall_security_posture'] in ['CRITICAL', 'HIGH_RISK']:
        print(f"\n⚠️  SECURITY ISSUES DETECTED - Review report for details")
        sys.exit(1)
    else:
        print(f"\n✅ Security posture acceptable")
        sys.exit(0)


if __name__ == "__main__":
    main() 