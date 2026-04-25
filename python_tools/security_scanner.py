"""
Web Application Security Scanner - Production Ready
Comprehensive vulnerability assessment tool for websites
Generates detailed PDF reports with findings and recommendations

Usage:
    python security_scanner.py
    Then enter target URL when prompted
"""

import sys
import json
import re
import requests
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse, urljoin
from collections import defaultdict

import urllib3

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

# ============================================================================
# API KEY PATTERNS (Based on keyhacks repository)
# ============================================================================

API_KEY_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws_secret_access_key=[\w/+=]{40}',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'GitHub PAT': r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
    'Stripe API Key (Live)': r'sk_live_[0-9a-zA-Z]{24,}',
    'Stripe API Key (Test)': r'sk_test_[0-9a-zA-Z]{24,}',
    'Slack Bot Token': r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,38}',
    'Slack Webhook': (
        r'https://hooks.slack.com/services/'
        r'T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}'
    ),
    'Slack OAuth Token': r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Token': r'ya29\.[0-9A-Za-z\-_]{20,}',
    'Firebase Token': r'AIza[0-9A-Za-z\-_]{35}',
    'Mailchimp API Key': r'[a-z0-9]{32}-us[0-9]{1,2}',
    'Twilio API': r'AC[a-zA-Z0-9_]{32}',
    'SendGrid API': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    'HubSpot API': (
        r'(?i)(hubspot|hs_api)[_-]?key[_=\s]*[\'"]?[a-z0-9]{10}[\'"]?'
    ),
    'Heroku API': (
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    ),
    'Mailgun API': r'key-[0-9a-z]{32}',
    'Mapbox API': r'pk\.[a-zA-Z0-9_-]{60,}',
    'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[\w-]*',
    'Private SSH Key': r'-----BEGIN RSA PRIVATE KEY-----',
    'Database URL': r'(mongodb|postgres|mysql|redis)://[\w:@\./\?=&-]+',
    'API Key Generic': (
        r'api[_-]?key[\'\":\s=]*[\'\"]?[a-zA-Z0-9_-]{20,}[\'\"]?'
    ),
}

REQUIRED_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS - Forces HTTPS',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'X-Frame-Options': 'Prevents clickjacking',
    'X-XSS-Protection': 'XSS protection',
    'Content-Security-Policy': 'CSP - XSS prevention',
    'Referrer-Policy': 'Controls referrer info',
}

CORS_TEST_ORIGINS = [
    'http://malicious-site.com',
    'https://attacker.example.com',
    'http://localhost:3000',
]

# ============================================================================
# SECURITY SCANNER CLASS
# ============================================================================


class SecurityScanner:
    """Main security scanning engine"""

    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.results = {
            'metadata': {},
            'vulnerabilities': [],
            'api_keys_found': [],
            'security_headers': {},
            'authentication': {},
            'cors': {},
            'rate_limiting': {},
            'ssl_tls': {},
        }

        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme
        self.base_url = f"{self.scheme}://{self.domain}"

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36'
            ),
        })

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def log(self, message: str, level: str = "INFO"):
        """Print log messages"""
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [{level}] {message}")

    def scan(self) -> Dict:
        """Execute full security scan"""
        self.log("=" * 80)
        self.log(f"Starting security scan for: {self.target_url}")
        self.log("=" * 80)

        self.log("\n[1/8] Collecting metadata...")
        self._collect_metadata()

        self.log("[2/8] Checking SSL/TLS configuration...")
        self._check_ssl_tls()

        self.log("[3/8] Scanning security headers...")
        self._check_security_headers()

        self.log("[4/8] Testing CORS configuration...")
        self._test_cors()

        self.log("[5/8] Testing rate limiting...")
        self._test_rate_limiting()

        self.log("[6/8] Checking authentication mechanisms...")
        self._check_authentication()

        self.log("[7/8] Scanning for leaked API keys...")
        self._scan_for_api_keys()

        self.log("[8/8] Testing for common vulnerabilities...")
        self._test_vulnerabilities()

        self.log("\n" + "=" * 80)
        self.log("Security scan completed!")
        self.log("=" * 80)

        return self.results

    def _collect_metadata(self):
        """Collect basic metadata about the target"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            self.results['metadata'] = {
                'url': self.target_url,
                'domain': self.domain,
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'server': response.headers.get('Server', 'Not disclosed'),
                'scan_time': datetime.now().isoformat(),
            }

            self.log(f"Status Code: {response.status_code}")
            self.log(f"Server: {response.headers.get('Server', 'Not disclosed')}")

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        try:
            if self.scheme == 'https':
                self.results['ssl_tls']['https_enabled'] = True
                self.log("✓ HTTPS is enabled")

                try:
                    response = self.session.get(self.target_url, verify=True, timeout=10)
                    self.results['ssl_tls']['certificate_valid'] = True
                    self.log("✓ Valid SSL certificate")
                except requests.exceptions.SSLError:
                    self.results['ssl_tls']['certificate_valid'] = False
                    self.log("✗ SSL certificate validation failed", "WARNING")
                    self.results['vulnerabilities'].append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'HIGH',
                        'description': 'SSL certificate validation failed'
                    })
            else:
                self.results['ssl_tls']['https_enabled'] = False
                self.log("✗ HTTPS not enabled", "WARNING")
                self.results['vulnerabilities'].append({
                    'type': 'Missing HTTPS',
                    'severity': 'CRITICAL',
                    'description': 'Website does not use HTTPS'
                })
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers

            for header, description in REQUIRED_SECURITY_HEADERS.items():
                if header in headers:
                    self.results['security_headers'][header] = {'present': True}
                    self.log(f"✓ {header}")
                else:
                    self.results['security_headers'][header] = {'present': False}
                    self.log(f"✗ Missing: {header}", "WARNING")
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'description': f'Missing header: {header}'
                    })
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _test_cors(self):
        """Test CORS configuration"""
        try:
            self.log("\nTesting CORS...")

            response = self.session.get(self.target_url, timeout=10, verify=False)
            cors_allow_origin = response.headers.get('Access-Control-Allow-Origin')

            self.results['cors'] = {'allow_origin': cors_allow_origin, 'tests': []}

            if cors_allow_origin == '*':
                self.log("✗ CORS allows wildcard (*)", "WARNING")
                self.results['vulnerabilities'].append({
                    'type': 'Invalid CORS Configuration',
                    'severity': 'HIGH',
                    'description': 'Access-Control-Allow-Origin set to wildcard (*)'
                })
            elif not cors_allow_origin:
                self.log("✓ No CORS headers (restrictive)")
            else:
                self.log(f"ℹ CORS Allow-Origin: {cors_allow_origin}")

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _test_rate_limiting(self):
        """Test for rate limiting"""
        try:
            self.log("\nTesting rate limiting (50 requests)...")

            requests_successful = 0
            blocked_count = 0

            for i in range(50):
                try:
                    response = self.session.get(self.target_url, timeout=5, verify=False)
                    requests_successful += 1

                    if response.status_code == 429:
                        blocked_count += 1
                except:
                    blocked_count += 1

            self.results['rate_limiting'] = {
                'requests_sent': 50,
                'successful': requests_successful,
                'blocked': blocked_count,
            }

            if blocked_count == 0:
                self.log(f"✗ NO RATE LIMITING - {requests_successful} requests succeeded", "WARNING")
                self.results['vulnerabilities'].append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'HIGH',
                    'description': f'No rate limiting detected - {requests_successful} requests succeeded'
                })
            else:
                self.log(
                    f"✓ Rate limiting detected - "
                    f"{blocked_count} requests blocked"
                )

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _check_authentication(self):
        """Check authentication mechanisms"""
        try:
            self.log("\nChecking authentication...")

            response = self.session.get(self.target_url, timeout=10, verify=False)

            if '/api/' in self.target_url:
                if response.status_code in [200, 201]:
                    self.log("✗ API accessible without authentication", "WARNING")
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Authentication',
                        'severity': 'CRITICAL',
                        'description': 'API endpoints accessible without authentication'
                    })
                else:
                    self.log("✓ Authentication appears required")

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _scan_for_api_keys(self):
        """Scan page content for leaked API keys"""
        try:
            self.log("\nScanning for exposed API keys...")

            response = self.session.get(self.target_url, timeout=10, verify=False)
            page_content = response.text
            headers_text = json.dumps(dict(response.headers))
            search_content = page_content + headers_text

            api_keys_found = []

            for key_name, pattern in API_KEY_PATTERNS.items():
                matches = re.findall(pattern, search_content)

                if matches:
                    self.log(f"⚠ Found {key_name}: {len(matches)} match(es)", "WARNING")

                    for match in matches[:1]:
                        api_keys_found.append({
                            'type': key_name,
                            'value': match[:20] + '***',
                        })
                        self.results['vulnerabilities'].append({
                            'type': 'Exposed API Key',
                            'severity': 'CRITICAL',
                            'description': f'Potential {key_name} found in page content'
                        })

            self.results['api_keys_found'] = api_keys_found

            if not api_keys_found:
                self.log("✓ No obvious API keys detected")

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")

    def _test_vulnerabilities(self):
        """Test for common vulnerabilities"""
        try:
            self.log("\nScanning for common vulnerabilities...")

            sensitive_paths = ['/.env', '/config.php', '/.git/config', '/web.config']

            for path in sensitive_paths:
                try:
                    response = self.session.get(
                        urljoin(self.base_url, path), timeout=5, verify=False
                    )
                    if response.status_code == 200:
                        self.log(f"⚠ Sensitive file accessible: {path}", "WARNING")
                        self.results['vulnerabilities'].append({
                            'type': 'Information Disclosure',
                            'severity': 'HIGH',
                            'description': f'Sensitive file {path} is publicly accessible'
                        })
                except:
                    pass

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")


# ============================================================================
# PDF REPORT GENERATOR CLASS
# ============================================================================

class PDFReportGenerator:
    """Generate PDF report from scan results"""

    def __init__(self, results: Dict, target_url: str):
        self.results = results
        self.target_url = target_url
        self.doc = None
        self.story = []
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#d32f2f'),
            spaceAfter=30,
            alignment=TA_CENTER,
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1976d2'),
            spaceAfter=12,
            spaceBefore=12,
        ))

    def generate(self, output_path: str = 'security_report.pdf'):
        """Generate complete security report"""
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
        )

        self.story = []

        # Title
        self._add_title_page()
        self.story.append(PageBreak())

        # Executive Summary
        self._add_executive_summary()
        self.story.append(PageBreak())

        # Vulnerabilities
        self._add_vulnerabilities_section()
        self.story.append(PageBreak())

        # Security Headers
        self._add_security_headers_section()
        self.story.append(PageBreak())

        # CORS
        self._add_cors_section()
        self.story.append(PageBreak())

        # Rate Limiting
        self._add_rate_limiting_section()
        self.story.append(PageBreak())

        # API Keys
        self._add_api_keys_section()
        self.story.append(PageBreak())

        # Recommendations
        self._add_recommendations_section()

        try:
            self.doc.build(self.story)
            print(f"\n✓ PDF Report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"✗ Error generating PDF: {str(e)}")
            return None

    def _add_title_page(self):
        title = Paragraph(
            "Security Assessment Report", self.styles['CustomTitle']
        )
        self.story.append(title)
        self.story.append(Spacer(1, 0.3*inch))

        meta = [
            f"<b>Target URL:</b> {self.target_url}",
            f"<b>Scan Date:</b> {self.results['metadata'].get('scan_time', 'N/A')}",
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]

        for data in meta:
            self.story.append(Paragraph(data, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))

    def _add_executive_summary(self):
        self.story.append(Paragraph("Executive Summary", self.styles['SectionHeading']))

        vulns = self.results.get('vulnerabilities', [])
        critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])

        summary_text = f"""
        Comprehensive security scan of {self.target_url}.<br/><br/>
        <b>Vulnerability Summary:</b><br/>
        • <font color="red"><b>CRITICAL:</b> {critical}</font><br/>
        • <font color="orange"><b>HIGH:</b> {high}</font><br/>
        • <b>MEDIUM:</b> {medium}<br/><br/>
        <b>Total Vulnerabilities:</b> <b>{len(vulns)}</b>
        """

        self.story.append(Paragraph(summary_text, self.styles['BodyText']))

    def _add_vulnerabilities_section(self):
        self.story.append(Paragraph("Identified Vulnerabilities", self.styles['SectionHeading']))

        vulns = self.results.get('vulnerabilities', [])

        if not vulns:
            self.story.append(Paragraph("✓ No vulnerabilities detected", self.styles['Normal']))
            return

        for vuln in vulns[:20]:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            description = vuln.get('description', '')

            color_map = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 'MEDIUM': '#fbc02d'}
            color = color_map.get(severity, '#000000')

            vuln_html = f"""
            <font color="{color}"><b>[{severity}]</b></font> <b>{vuln_type}</b><br/>
            {description}<br/>
            """

            self.story.append(Paragraph(vuln_html, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))

    def _add_security_headers_section(self):
        self.story.append(Paragraph("Security Headers", self.styles['SectionHeading']))

        headers = self.results.get('security_headers', {})

        table_data = [['Header', 'Status']]
        for header, data in headers.items():
            status = '✓ Present' if data.get('present') else '✗ Missing'
            table_data.append([header, status])

        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        self.story.append(table)

    def _add_cors_section(self):
        self.story.append(Paragraph("CORS Configuration", self.styles['SectionHeading']))

        cors = self.results.get('cors', {})
        cors_html = f"<b>Allow-Origin:</b> {cors.get('allow_origin', 'Not set')}<br/>"
        self.story.append(Paragraph(cors_html, self.styles['Normal']))

    def _add_rate_limiting_section(self):
        self.story.append(Paragraph("Rate Limiting Analysis", self.styles['SectionHeading']))

        rl = self.results.get('rate_limiting', {})
        rl_html = f"""
        <b>Requests Sent:</b> {rl.get('requests_sent', 'N/A')}<br/>
        <b>Successful:</b> {rl.get('successful', 'N/A')}<br/>
        <b>Blocked (429):</b> {rl.get('blocked', 'N/A')}<br/>
        """
        self.story.append(Paragraph(rl_html, self.styles['Normal']))

    def _add_api_keys_section(self):
        self.story.append(Paragraph("Exposed API Keys", self.styles['SectionHeading']))

        api_keys = self.results.get('api_keys_found', [])

        if not api_keys:
            self.story.append(Paragraph("✓ No obvious API keys detected", self.styles['Normal']))
            return

        self.story.append(Paragraph(
            f"<font color='#d32f2f'><b>⚠ {len(api_keys)} API keys found</b></font>",
            self.styles['Normal']
        ))

        for key in api_keys:
            key_html = f"<b>{key.get('type')}:</b> {key.get('value')}<br/>"
            self.story.append(Paragraph(key_html, self.styles['Normal']))

    def _add_recommendations_section(self):
        self.story.append(Paragraph("Recommendations", self.styles['SectionHeading']))

        recommendations = [
            "<b>1. Implement Rate Limiting:</b> 100 req/min per IP",
            "<b>2. Enforce Authentication:</b> JWT or OAuth2 required",
            "<b>3. Configure CORS:</b> Only allow trusted origins",
            "<b>4. Add Security Headers:</b> HSTS, CSP, X-Frame-Options",
            "<b>5. Remove Hardcoded Secrets:</b> Use environment variables",
            "<b>6. Enable HTTPS:</b> Force HTTPS redirect",
            "<b>7. Input Validation:</b> Sanitize all user inputs",
            "<b>8. Security Scanning:</b> Integrate into CI/CD",
        ]

        for rec in recommendations:
            self.story.append(Paragraph(rec, self.styles['Normal']))
            self.story.append(Spacer(1, 0.08*inch))


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1].strip()
    else:
        target_url = input("Enter target website URL (e.g., https://example.com): ").strip()

    if not target_url:
        print("No URL provided")
        sys.exit(1)

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    print(f"\n🔍 Starting security scan for: {target_url}\n")

    scanner = SecurityScanner(target_url, verbose=True)
    results = scanner.scan()

    print("\n📄 Generating PDF report...")
    report_generator = PDFReportGenerator(results, target_url)
    report_file = report_generator.generate('security_assessment_report.pdf')

    if report_file:
        print(f"✅ Report saved to: {report_file}")

        vulns = results['vulnerabilities']
        print("\n📊 Vulnerability Summary:")
        print(f"Total: {len(vulns)}")

        by_severity = defaultdict(int)
        for vuln in vulns:
            by_severity[vuln.get('severity', 'Unknown')] += 1

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            print(f"  {severity}: {by_severity.get(severity, 0)}")

        with open('scan_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print("\n📋 Detailed results saved to: scan_results.json")
    else:
        print("❌ Failed to generate report")
        sys.exit(1)


if __name__ == '__main__':
    main()
