import email
import re
import dns.resolver
import socket
from email.parser import HeaderParser

class EmailHeaderAnalyzer:
    def __init__(self):
        self.spoofing_indicators = []
        self.auth_results = {
            'spf': None,
            'dkim': None,
            'dmarc': None
        }

    def parse_email_headers(self, raw_headers):
        """Parse raw email headers into a structured format."""
        parser = HeaderParser()
        return parser.parsestr(raw_headers)

    def check_sender_consistency(self, headers):
        """Check for consistency between From, Return-Path, and Reply-To headers."""
        from_header = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        reply_to = headers.get('Reply-To', '')
        
        # Extract email addresses from headers
        from_email = self._extract_email(from_header)
        return_path_email = self._extract_email(return_path)
        reply_to_email = self._extract_email(reply_to)
        
        # Check for inconsistencies
        if from_email and return_path_email and from_email != return_path_email:
            self.spoofing_indicators.append(f"Sender mismatch: From '{from_email}' vs Return-Path '{return_path_email}'")
        
        if from_email and reply_to_email and from_email != reply_to_email:
            self.spoofing_indicators.append(f"Sender mismatch: From '{from_email}' vs Reply-To '{reply_to_email}'")
            
        return from_email, return_path_email, reply_to_email

    def check_received_headers(self, headers):
        """Analyze Received headers to trace email path."""
        received_headers = headers.get_all('Received', [])
        ip_addresses = []
        
        for header in received_headers:
            # Extract IP addresses from Received headers
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            ip_addresses.extend(ips)
            
        # Check for suspicious relay paths
        if len(ip_addresses) > 5:
            self.spoofing_indicators.append(f"Suspicious email routing: {len(ip_addresses)} hops detected")
            
        return ip_addresses

    def check_authentication_results(self, headers):
        """Check SPF, DKIM, and DMARC authentication results."""
        auth_results = headers.get('Authentication-Results', '')
        
        # Check SPF
        spf_match = re.search(r'spf=(\w+)', auth_results)
        if spf_match:
            self.auth_results['spf'] = spf_match.group(1)
            if self.auth_results['spf'] not in ['pass', 'neutral']:
                self.spoofing_indicators.append(f"SPF authentication failed: {self.auth_results['spf']}")
        
        # Check DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        if dkim_match:
            self.auth_results['dkim'] = dkim_match.group(1)
            if self.auth_results['dkim'] != 'pass':
                self.spoofing_indicators.append(f"DKIM authentication failed: {self.auth_results['dkim']}")
        
        # Check DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        if dmarc_match:
            self.auth_results['dmarc'] = dmarc_match.group(1)
            if self.auth_results['dmarc'] != 'pass':
                self.spoofing_indicators.append(f"DMARC authentication failed: {self.auth_results['dmarc']}")
        
        return self.auth_results

    def verify_spf_manually(self, sender_domain, sender_ip):
        """Manually verify SPF record for the sender's domain."""
        try:
            # Query DNS for SPF record
            answers = dns.resolver.resolve(sender_domain, 'TXT')
            spf_record = None
            
            # Find SPF record
            for rdata in answers:
                if 'v=spf1' in rdata.to_text():
                    spf_record = rdata.to_text()
                    break
            
            if not spf_record:
                self.spoofing_indicators.append(f"No SPF record found for {sender_domain}")
                return False
            
            # Basic check if IP is allowed in SPF
            # Note: This is a simplified check, full SPF evaluation is more complex
            if sender_ip in spf_record:
                return True
            elif 'a' in spf_record.lower() or 'mx' in spf_record.lower() or 'include:' in spf_record.lower():
                return "Needs full SPF evaluation"
            else:
                self.spoofing_indicators.append(f"Sender IP {sender_ip} not explicitly allowed in SPF record")
                return False
                
        except Exception as e:
            self.spoofing_indicators.append(f"SPF verification error: {str(e)}")
            return False

    def analyze_headers(self, raw_headers):
        """Main function to analyze email headers for spoofing indicators."""
        headers = self.parse_email_headers(raw_headers)
        
        # Run all checks
        sender_info = self.check_sender_consistency(headers)
        ip_path = self.check_received_headers(headers)
        auth_results = self.check_authentication_results(headers)
        
        # Extract sender domain for additional checks
        from_email = sender_info[0]
        sender_domain = from_email.split('@')[-1] if '@' in from_email else None
        
        # Extract sending IP (usually the first one in the path)
        sending_ip = ip_path[0] if ip_path else None
        
        # If we have both domain and IP, verify SPF manually
        if sender_domain and sending_ip:
            spf_result = self.verify_spf_manually(sender_domain, sending_ip)
            if spf_result != True:
                self.auth_results['manual_spf'] = spf_result
        
        # Compile analysis results
        results = {
            'sender_info': sender_info,
            'ip_path': ip_path,
            'auth_results': self.auth_results,
            'spoofing_indicators': self.spoofing_indicators,
            'risk_level': self._calculate_risk_level()
        }
        
        return results
    
    def _extract_email(self, header_value):
        """Extract email address from header value."""
        matches = re.findall(r'[\w\.-]+@[\w\.-]+', header_value)
        return matches[0] if matches else ""
    
    def _calculate_risk_level(self):
        """Calculate spoofing risk level based on indicators."""
        if not self.spoofing_indicators:
            return "Low"
        elif len(self.spoofing_indicators) <= 2:
            return "Medium"
        else:
            return "High"

    def generate_report(self, analysis_results):
        """Generate a user-friendly report from analysis results."""
        report = []
        report.append("EMAIL HEADER ANALYSIS REPORT")
        report.append("===========================")
        
        # Risk assessment
        report.append(f"RISK LEVEL: {analysis_results['risk_level']}")
        
        # Sender information
        report.append("\nSENDER INFORMATION:")
        report.append(f"From: {analysis_results['sender_info'][0]}")
        report.append(f"Return-Path: {analysis_results['sender_info'][1]}")
        report.append(f"Reply-To: {analysis_results['sender_info'][2]}")
        
        # Authentication results
        report.append("\nAUTHENTICATION RESULTS:")
        report.append(f"SPF: {analysis_results['auth_results']['spf'] or 'Not found'}")
        report.append(f"DKIM: {analysis_results['auth_results']['dkim'] or 'Not found'}")
        report.append(f"DMARC: {analysis_results['auth_results']['dmarc'] or 'Not found'}")
        
        # Email routing
        report.append("\nEMAIL ROUTING:")
        for i, ip in enumerate(analysis_results['ip_path']):
            report.append(f"Hop {i+1}: {ip}")
            
        # Spoofing indicators
        if analysis_results['spoofing_indicators']:
            report.append("\nSPOOFING INDICATORS DETECTED:")
            for indicator in analysis_results['spoofing_indicators']:
                report.append(f"- {indicator}")
            
            # Recommendations
            report.append("\nRECOMMENDATIONS:")
            if analysis_results['risk_level'] == "High":
                report.append("- Do not trust this email or click on any links/attachments")
                report.append("- Report this email to your security team")
            elif analysis_results['risk_level'] == "Medium":
                report.append("- Treat this email with caution")
                report.append("- Verify the sender through other channels before taking action")
        else:
            report.append("\nNo spoofing indicators detected. This email appears legitimate.")
            
        return "\n".join(report)


# Example usage
if __name__ == "__main__":
    # Sample raw email headers (in a real app, these would be extracted from an email)
    sample_headers = """Return-Path: <sender@example.com>
Received: from mail-server.example.org (mail-server.example.org [192.168.1.1])
    by inbound.mail.com (Server) with SMTP id abcdef123
    for <recipient@domain.com>; Mon, 24 Mar 2025 10:00:00 -0700 (PDT)
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of sender@example.com designates 192.168.1.1 as permitted sender) smtp.mailfrom=sender@example.com;
    dkim=pass header.i=@example.com;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;
    h=from:to:subject:date; bh=...base64data...; b=...base64signature...
From: "Sender Name" <sender@example.com>
Reply-To: "Sender Name" <sender@example.com>
To: "Recipient" <recipient@domain.com>
Subject: Test Email
Date: Mon, 24 Mar 2025 10:00:00 -0700
"""

    analyzer = EmailHeaderAnalyzer()
    results = analyzer.analyze_headers(sample_headers)
    report = analyzer.generate_report(results)
    print(report)