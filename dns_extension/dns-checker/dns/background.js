console.log(`DNS & Email Spoofing Detector`);

// Configuration for known domains and their expected IPs
const DOMAIN_IP_WHITELIST = {
    "google.com": ["172.217.0.0/16", "216.58.192.0/19"],
    "github.com": ["140.82.112.0/20", "192.30.255.0/24"],
    "microsoft.com": ["13.64.0.0/11", "40.112.0.0/13"],
    "amazon.com": ["52.84.0.0/15", "54.239.128.0/18"]
};

// IP range checking utility
function isIPInRange(ip, cidrRanges) {
    const ipToNumber = (ip) => {
        return ip.split('.').reduce((acc, octet) => (acc * 256) + parseInt(octet), 0);
    };

    const ipNum = ipToNumber(ip);
    
    return cidrRanges.some(cidr => {
        const [network, bits] = cidr.split('/');
        const networkNum = ipToNumber(network);
        const mask = ~((1 << (32 - parseInt(bits))) - 1);
        
        return (ipNum & mask) === (networkNum & mask);
    });
}

async function checkDNSSpoofing(tabUrl) {
    try {
        const domain = new URL(tabUrl).hostname;
        console.log(`🔍 Checking DNS for: ${domain}`);

        let resolvedIPs = new Set();
        const DNS_PROVIDERS = [
            "https://dns.google/resolve?name=",
            "https://cloudflare-dns.com/dns-query?name="
        ];

        // Query multiple DNS providers
        for (const provider of DNS_PROVIDERS) {
            try {
                const response = await fetch(`${provider}${domain}&type=A`, {
                    headers: { "Accept": "application/dns-json" }
                });
                const data = await response.json();

                if (data.Answer) {
                    data.Answer.forEach(entry => {
                        if (entry.type === 1) resolvedIPs.add(entry.data); // Type 1 = A record
                    });
                }
            } catch (err) {
                console.warn(`⚠️ Error querying ${provider}:`, err);
            }
        }

        resolvedIPs = Array.from(resolvedIPs);
        console.log(`✅ DNS Records for ${domain}:`, resolvedIPs);

        if (resolvedIPs.length === 0) {
            showNotification("⚠️ DNS Warning", `No DNS records found for ${domain}`);
            return;
        }

        // IP Validation against Expected IPs
        let ipValidationResult = {
            trusted: false,
            matchedExpectedIP: false,
            details: []
        };

        // Check if domain is in whitelist
        if (DOMAIN_IP_WHITELIST[domain]) {
            const expectedRanges = DOMAIN_IP_WHITELIST[domain];
            
            resolvedIPs.forEach(ip => {
                const isExpectedIP = isIPInRange(ip, expectedRanges);
                
                ipValidationResult.details.push({
                    ip: ip,
                    isExpected: isExpectedIP,
                    expectedRanges: expectedRanges
                });

                if (isExpectedIP) {
                    ipValidationResult.matchedExpectedIP = true;
                }
            });

            // Consider trusted if at least one IP matches expected ranges
            ipValidationResult.trusted = ipValidationResult.matchedExpectedIP;
        } else {
            // For domains not in whitelist, do additional checks
            let trusted = true;
            for (const ip of resolvedIPs) {
                try {
                    const asnData = await fetch(`https://ipinfo.io/${ip}/json`);
                    const asnInfo = await asnData.json();

                    const trustedCompanies = [
                        "Google", "Cloudflare", "Amazon", "Microsoft",
                        "Akamai", "Fastly", "Meta", "Facebook",
                        "Apple", "Disney", "PayPal", "Edgecast", "Flipkart",
                        "Bank", "Financial", "SBI", "Indian Bank", "Canara Bank"
                    ];

                    // Check if ASN data matches trusted companies
                    if (!trustedCompanies.some(company => (asnInfo.org || "").includes(company))) {
                        trusted = false;
                    }
                } catch (error) {
                    console.warn(`⚠️ Error fetching ASN info for IP: ${ip}`, error);
                }
            }
            ipValidationResult.trusted = trusted;
        }

        // Notification based on validation results
        if (ipValidationResult.trusted) {
            showNotification("✅ Trusted DNS", `Domain ${domain} resolves to trusted networks.`);
        } else {
            let notificationMessage = `⚠️ Possible DNS Spoofing! 
Domain: ${domain}
Resolved IPs: ${resolvedIPs.join(', ')}`;
            
            // Add detailed IP validation info to notification
            if (ipValidationResult.details.length > 0) {
                notificationMessage += "\n\nIP Validation:";
                ipValidationResult.details.forEach(detail => {
                    notificationMessage += `\n- IP ${detail.ip}: ${detail.isExpected ? '✅ Expected' : '❌ Unexpected'}`;
                });
            }

            showNotification("⚠️ DNS Spoofing Alert", notificationMessage);
        }

    } catch (error) {
        console.error("⚠️ Error checking DNS spoofing:", error);
    }
}

// Existing notification and runtime message listener functions remain the same
function showNotification(title, message) {
    chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: title,
        message: message
    });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "check_dns" && request.url) {
        console.log("🔍 DNS check initiated for:", request.url);
        checkDNSSpoofing(request.url);
        sendResponse({ status: "DNS check in progress. Notification will appear shortly!" });
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
        checkDNSSpoofing(tab.url);
    }
});
