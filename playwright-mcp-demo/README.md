# Playwright MCP OWASP Security Tester

An MCP (Model Context Protocol) server that performs OWASP Top 10 security tests against websites using Playwright.

## Features

This MCP server provides comprehensive security testing tools based on the OWASP Top 10 2021:

### Individual Security Tests

1. **A01: Broken Access Control** (`test_broken_access_control`)
   - Tests for unauthorized access to admin paths
   - Directory traversal vulnerability detection
   - Access control bypass testing

2. **A02: Cryptographic Failures** (`test_cryptographic_failures`)
   - HTTPS/HTTP protocol analysis
   - Mixed content detection
   - SSL/TLS configuration checks
   - Sensitive data transmission security

3. **A03: Injection** (`test_injection_vulnerabilities`)
   - SQL injection testing
   - Cross-Site Scripting (XSS) detection
   - Command injection analysis
   - Custom payload testing support

4. **A04: Insecure Design** (`test_insecure_design`)
   - Security headers analysis
   - Information disclosure in HTML comments
   - Password field security configuration
   - Rate limiting assessment

5. **A05: Security Misconfiguration** (`test_security_misconfiguration`)
   - Default/common file accessibility
   - Server information disclosure
   - Directory listing detection
   - Configuration file exposure

6. **A06: Vulnerable and Outdated Components** (`test_vulnerable_components`)
   - JavaScript library version detection
   - Known vulnerable version identification
   - CMS/framework detection
   - Technology stack analysis

7. **A07: Identification and Authentication Failures** (`test_auth_failures`)
   - Password policy analysis
   - Session management security
   - Cookie security attributes
   - Authentication mechanism testing

8. **A08: Software and Data Integrity Failures** (`test_integrity_failures`)
   - Subresource Integrity (SRI) checks
   - Content Security Policy analysis
   - File upload security
   - Unsafe deserialization detection

9. **A09: Security Logging and Monitoring Failures** (`test_logging_monitoring`)
   - Error information disclosure
   - Debug information exposure
   - Request tracking capabilities
   - Monitoring mechanism analysis

10. **A10: Server-Side Request Forgery (SSRF)** (`test_ssrf_vulnerabilities`)
    - URL input validation testing
    - Internal address access attempts
    - Webhook/callback functionality analysis
    - API endpoint SSRF protection

### Comprehensive Testing

- **Full OWASP Scan** (`run_full_owasp_scan`)
  - Runs all 10 OWASP Top 10 tests in sequence
  - Provides comprehensive security assessment
  - Generates summary report with recommendations

## Installation

1. Install dependencies:
```bash
npm install
```

2. Build the project:
```bash
npm run build
```

## Usage

### With Claude Desktop

Add to your Claude Desktop configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "owasp-security-tester": {
      "command": "node",
      "args": ["/absolute/path/to/playwright-mcp-demo/build/index.js"]
    }
  }
}
```

### Example Commands

After connecting to Claude Desktop, you can use commands like:

- "Run a comprehensive OWASP security scan on https://thyaga.lk/"
- "Test for broken access control vulnerabilities on https://example.com"
- "Check for injection vulnerabilities on this website"
- "Analyze the cryptographic security of https://mysite.com"

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorized Testing Only**: Only use this tool on websites you own or have explicit permission to test
2. **Responsible Disclosure**: Report any vulnerabilities found through proper channels
3. **Rate Limiting**: The tool implements basic delays to avoid overwhelming target servers
4. **Non-Destructive**: All tests are designed to be read-only and non-destructive
5. **False Positives**: Automated scans may produce false positives - manual verification is recommended

## Limitations

- This is an automated scanning tool and cannot replace manual security testing
- Some vulnerabilities require human analysis and cannot be detected automatically
- The tool provides basic security checks and should be supplemented with comprehensive security assessments
- Network restrictions or bot detection may limit scan effectiveness

## Target Website

The tool has been specifically configured to test https://thyaga.lk/ but can be used on any website with proper authorization.

## Development

- **Language**: TypeScript
- **Browser Engine**: Playwright (Chromium)
- **Protocol**: Model Context Protocol (MCP)
- **Architecture**: Server-side security testing with AI integration

## Contributing

This is a demonstration project showing how to integrate security testing with AI through MCP. Feel free to extend it with additional security tests or improve existing ones.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any websites. The authors are not responsible for any misuse of this tool.
