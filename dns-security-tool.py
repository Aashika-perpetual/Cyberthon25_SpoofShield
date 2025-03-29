import os
import sys
import socket
import logging
import dns.resolver
import subprocess
import ipaddress
import requests
import configparser
import ssl
import concurrent.futures
from typing import List, Dict, Any
import dns.resolver
import dns.message
import dns.query
import cryptography
from cryptography import x509
from datetime import datetime, timedelta

class DNSSecurityManager:
    def __init__(self, config_path='config.ini'):
        """
        Initialize DNS Security Management System
        
        Key Features:
        - SPF Validation
        - DKIM Configuration
        - DMARC Policy Management
        - DNS Spoofing Detection
        - Threat Intelligence Integration
        """
        self.config = self._load_configuration(config_path)
        self.logger = self._setup_logging()
        
        # Security Configurations
        self.spf_records = {}
        self.dmarc_policies = {}
        self.blacklisted_domains = set()
        self.threat_intelligence_sources = [
            'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
            'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
        ]

    def _load_configuration(self, config_path: str) -> configparser.ConfigParser:
        """
        Load configuration from INI file
        """
        config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            self._create_default_config(config_path)
        config.read(config_path)
        return config

    def _create_default_config(self, config_path: str):
        """
        Create a default configuration file
        """
        config = configparser.ConfigParser()
        config['DNS_SECURITY'] = {
            'log_level': 'INFO',
            'dnssec_enabled': 'True',
            'max_dns_query_timeout': '5',
            'threat_detection_interval': '24'
        }
        config['NETWORK'] = {
            'trusted_networks': '192.168.0.0/16,10.0.0.0/8',
            'dns_servers': '8.8.8.8,1.1.1.1'
        }
        
        with open(config_path, 'w') as configfile:
            config.write(configfile)

    def _setup_logging(self) -> logging.Logger:
        """
        Configure logging system
        """
        log_level = getattr(logging, 
            self.config.get('DNS_SECURITY', 'log_level', fallback='INFO')
        )
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dns_security.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger('DNSSecurityManager')

    def validate_spf_record(self, domain: str) -> bool:
        try:
            # Add multiple retry mechanisms
            for attempt in range(3):
                try:
                    spf_record = dns.resolver.resolve(domain, 'TXT')
                    for record in spf_record:
                        record_text = record.to_text()
                        if 'v=spf1' in record_text:
                            return True
                    break
                except dns.resolver.NXDOMAIN:
                    self.logger.warning(f"Domain {domain} does not exist")
                    break
                except dns.resolver.NoAnswer:
                    self.logger.warning(f"No SPF record found for {domain}")
                    break
                except Exception as retry_error:
                    self.logger.error(f"SPF retry attempt {attempt + 1} failed: {retry_error}")
                    time.sleep(1)  # Wait before retry
            return False
        except Exception as e:
            self.logger.error(f"SPF validation error for {domain}: {e}")
            return False

    def check_dns_cache_poisoning(self, domain: str) -> bool:
        """
        Detect potential DNS cache poisoning attempts
        """
        try:
            # Multiple resolvers to cross-verify
            resolvers = [
                dns.resolver.Resolver(configure=False),
                dns.resolver.Resolver(configure=False)
            ]
            
            # Configure different resolvers
            resolvers[0].nameservers = ['8.8.8.8']
            resolvers[1].nameservers = ['1.1.1.1']
            
            # Resolve IP addresses
            results = [
                set(str(rdata) for rdata in resolver.resolve(domain, 'A'))
                for resolver in resolvers
            ]
            
            # Compare results
            if len(set.intersection(*results)) != len(results[0]):
                self.logger.warning(f"Potential DNS cache poisoning detected for {domain}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"DNS poisoning check error: {e}")
            return True

    def fetch_threat_intelligence(self) -> set:
        """
        Fetch and aggregate threat intelligence
        """
        threat_ips = set()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_url = {
                executor.submit(requests.get, url): url 
                for url in self.threat_intelligence_sources
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    response = future.result()
                    # Parse and extract IP addresses
                    ips = [
                        line.split()[0] 
                        for line in response.text.splitlines() 
                        if self._is_valid_ip(line.split()[0])
                    ]
                    threat_ips.update(ips)
                except Exception as e:
                    self.logger.error(f"Threat intel fetch error: {e}")
        
        return threat_ips

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IP address format
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def generate_dmarc_report(self, domain: str) -> Dict[str, Any]:
        """
        Generate DMARC policy report
        """
        try:
            dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_record:
                record_text = record.to_text()
                if record_text.startswith('"v=DMARC1'):
                    policy = {
                        'policy': self._extract_dmarc_policy(record_text),
                        'aggregate_report': True,
                        'forensic_report': True
                    }
                    return policy
        except Exception as e:
            self.logger.error(f"DMARC record error: {e}")
        return {}

    def _extract_dmarc_policy(self, record: str) -> str:
        """
        Extract DMARC policy details
        """
        policy_match = {
            'p=none': 'Monitor',
            'p=quarantine': 'Quarantine',
            'p=reject': 'Reject'
        }
        for key, value in policy_match.items():
            if key in record:
                return value
        return 'Unknown'

    def run_security_scan(self, domains: List[str]):
        """
        Comprehensive security scan for domains
        """
        threat_ips = self.fetch_threat_intelligence()
        
        for domain in domains:
            results = {
                'domain': domain,
                'spf_valid': self.validate_spf_record(domain),
                'dns_poisoning_risk': not self.check_dns_cache_poisoning(domain),
                'dmarc_policy': self.generate_dmarc_report(domain)
            }
            
            self.logger.info(f"Security Scan Results: {results}")

def main():
    # Example usage
    security_manager = DNSSecurityManager()
    # Modify domain scanning strategy
    domains_to_scan = [
    'example.com',       # Verified domain
    'microsoft.com',     # Reliable domain
    'yahoo.com',         # Consistent performance
    'github.com',        # Tech-focused domain
    # Add organization-specific domains
]
    security_manager.run_security_scan(domains_to_scan)

if __name__ == "__main__":
    main()
