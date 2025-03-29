console.log(`DNS & Email Spoofing Detector`);
async function checkDNSSpoofing(tabUrl) {
    try {
        const domain = new URL(tabUrl).hostname;
        console.log(`🔍 Checking DNS for: ${domain}`);

        let resolvedIPs = new Set();
        const DNS_PROVIDERS = [
            "https://dns.google/resolve?name=",
            "https://cloudflare-dns.com/dns-query?name=",
            "https://doh.opendns.com/dns-query?name="
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

        // WHOIS & ASN Checks
        let trusted = true;
        for (const ip of resolvedIPs) {
            try {
                const asnData = await fetch(`https://ipinfo.io/${ip}/json`);
                const asnInfo = await asnData.json();

                const whoisData = await fetch(`https://rdap.org/ip/${ip}`);
                const whoisInfo = await whoisData.json();

                console.log(`🔍 IP: ${ip}`);
                console.log(`    ASN: ${asnInfo.org || "Unknown"}`);
                console.log(`    WHOIS Name: ${whoisInfo.name || "Not Found"}`);

                const trustedCompanies = [
                    "Google", "Cloudflare", "Amazon", "Microsoft",
                    "Akamai", "Fastly", "Meta", "Facebook",
                    "Apple", "Disney", "PayPal", "Edgecast", "Flipkart",
                    "Bank", "Financial", "SBI", "Indian Bank", "Canara Bank"
                ];

                // Check if ASN or WHOIS data matches trusted companies
                if (!trustedCompanies.some(company => (asnInfo.org || "").includes(company)) &&
                    (!whoisInfo.name || !trustedCompanies.some(company => whoisInfo.name.includes(company)))) {
                    trusted = false;
                }

            } catch (error) {
                console.warn(`⚠️ Error fetching ASN/WHOIS info for IP: ${ip}`, error);
            }
        }

        // Show notification based on trust level
        if (trusted) {
            showNotification("✅ Trusted DNS", `Domain ${domain} resolves to trusted networks.`);
        } else {
            showNotification("⚠️ Possible DNS Spoofing!", `Domain ${domain} is resolving to untrusted IPs: ${resolvedIPs}`);
        }

    } catch (error) {
        console.error("⚠️ Error checking DNS spoofing:", error);
    }
}

//Function to Check Email Spoofing
async function checkEmailSpoofing() {
    try {
        const response = await fetch("https://api.hunter.io/v2/email-verifier?email=example@domain.com&api_key=YOUR_HUNTER_API_KEY");
        const data = await response.json();

        if (data.data && data.data.result) {
            const status = data.data.result;
            let message = "";

            if (status === "deliverable") {
                message = "✅ Email is valid and not spoofed.";
            } else if (status === "risky") {
                message = "⚠️ Warning: Email appears suspicious!";
            } else {
                message = "❌ Email is likely spoofed!";
            }

            showNotification("📧 Email Spoofing Check", message);
        } else {
            showNotification("⚠️ Error", "Failed to verify email.");
        }
    } catch (error) {
        console.error("⚠️ Error checking email spoofing:", error);
        showNotification("⚠️ Error", "An error occurred while checking email spoofing.");
    }
}

//Function to Show Chrome Notification
function showNotification(title, message) {
    chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: title,
        message: message
    });
}

//Run DNS Check on Every Page Load
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        checkDNSSpoofing(tab.url);
    }
});

//Unified Message Listener (For Popup Actions)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "check_dns") {
        checkDNSSpoofing(request.url);
        sendResponse({ status: "DNS check in progress. Notification will appear shortly!" });
    } else if (request.action === "check_email") {
        checkEmailSpoofing();
        sendResponse({ status: "Email check in progress. Notification will appear shortly!" });
    }
});
