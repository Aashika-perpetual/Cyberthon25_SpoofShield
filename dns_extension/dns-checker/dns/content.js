chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "checkEmailHeaders") {
        let headers = document.querySelectorAll("pre"); // Example: Gmail email headers
        let emailText = headers.length > 0 ? headers[0].innerText : "";
        checkEmailSpoofing(emailText);
    }
});
console.log("🚀 DNS Spoofing Detector Injected!");

// Function to check DNS Spoofing
async function checkDNSSpoofing() {
    const domain = window.location.hostname;
    console.log("🔍 Checking DNS for:", domain);

    try {
        const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
        const dnsData = await dnsResponse.json();

        if (dnsData.Answer) {
            const resolvedIPs = dnsData.Answer.map(entry => entry.data);
            console.log(`✅ DNS Records for ${domain}:`, resolvedIPs);
        } else {
            console.warn(`❌ No DNS records found for ${domain}`);
        }
    } catch (error) {
        console.error("⚠️ Error fetching DNS data:", error);
    }
}

// Run automatically when a page loads
checkDNSSpoofing();
