console.log("🚀 DNS Spoofing Detector Loaded!");

// Trusted IPs list (Modify as needed)
const EXPECTED_IPS = [
    "8.8.8.8",
    "8.8.4.4",
    "142.250.191.142",
    "142.250.191.46",
    "142.250.196.4",
    "142.250.191.78"
];

// Function to check DNS Spoofing using Google's Public DNS API
async function checkDNSSpoofing(tabUrl) {
    try {
        const domain = new URL(tabUrl).hostname;
        const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
        const dnsData = await dnsResponse.json();

        if (!dnsData.Answer) {
            console.warn(`❌ No DNS records found for ${domain}`);
            return;
        }

        const resolvedIPs = dnsData.Answer.map(entry => entry.data);
        console.log(`✅ DNS Records from Google for ${domain}:`, resolvedIPs);

        // Identify trusted and untrusted IPs
        const matchedIPs = resolvedIPs.filter(ip => EXPECTED_IPS.includes(ip));
        const unexpectedIPs = resolvedIPs.filter(ip => !EXPECTED_IPS.includes(ip));

        if (matchedIPs.length > 0) {
            showNotification("✅ Trusted IP Detected", `Domain ${domain} is resolving to expected IP(s): ${matchedIPs}`);
        }

        if (unexpectedIPs.length > 0) {
            showNotification("⚠️ DNS Spoofing Detected!", `Unexpected IP(s) detected for ${domain}: ${unexpectedIPs}`);
        }

    } catch (error) {
        console.error("⚠️ Error fetching DNS data:", error);
    }
}

// Function to show Chrome notifications
function showNotification(title, message) {
    chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png", // Ensure this file exists in your extension folder
        title: title,
        message: message
    }, function(notificationId) {
        if (chrome.runtime.lastError) {
            console.error("Notification Error:", chrome.runtime.lastError);
        }
    });
}

// Listen for tab updates and check DNS when a page loads
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
        checkDNSSpoofing(tab.url);
    }
});
