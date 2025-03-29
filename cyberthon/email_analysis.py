import re
import dns.resolver
import email
import sys

def parse_email_header(header_text):
    message = email.message_from_string(header_text)
    headers = {}
    for key, value in message.items():
        headers[key] = value
    return headers

def extract_ip(headers):
    received_headers = headers.get("Received", "")
    ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', received_headers)
    return ip_address[-1] if ip_address else None

def check_spf(domain, ip):
    try:
        answers = dns.resolver.resolve("{}".format(domain), 'TXT')
        for txt_record in answers:
            if "v=spf1" in txt_record.to_text():
                print("SPF Record Found:", txt_record.to_text())
                return txt_record.to_text()
    except Exception as e:
        print("Error checking SPF:", e)
    return None

def check_dkim(domain):
    try:
        selector = "default"  # Modify this if needed
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for txt_record in answers:
            print("DKIM Record Found:", txt_record.to_text())
            return txt_record.to_text()
    except Exception as e:
        print("Error checking DKIM:", e)
    return None

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for txt_record in answers:
            print("DMARC Record Found:", txt_record.to_text())
            return txt_record.to_text()
    except Exception as e:
        print("Error checking DMARC:", e)
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python email_analysis.py <email_header_file>")
        sys.exit(1)

    header_file = sys.argv[1]

    try:
        with open(header_file, 'r') as f:
            header_text = f.read()

        headers = parse_email_header(header_text)

        from_domain = headers.get("From", "").split('@')[-1]
        source_ip = extract_ip(headers)

        print("From Domain:", from_domain)
        print("Source IP:", source_ip)

        print("\n[Checking SPF]")
        check_spf(from_domain, source_ip)

        print("\n[Checking DKIM]")
        check_dkim(from_domain)

        print("\n[Checking DMARC]")
        check_dmarc(from_domain)

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
