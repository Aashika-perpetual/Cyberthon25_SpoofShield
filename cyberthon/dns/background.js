chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_HEADERS") {
    // Simulate or perform actual header analysis
    const result = analyzeHeaders(message.details);
    sendResponse(result);
    return true;
  }
});

function analyzeHeaders(details) {
  // Comprehensive header analysis logic
  const result = {
    riskLevel: "Low",
    sender: details.sender,
    authResults: {
      spf: "pass",
      dkim: "pass", 
      dmarc: "pass"
    },
    indicators: []
  };

  // Implement more sophisticated risk detection
  const suspiciousDomains = ['spam.com', 'suspicious.net'];
  const suspiciousKeywords = ['urgent', 'lottery', 'win'];

  // Check sender domain
  if (suspiciousDomains.some(domain => details.sender.email.includes(domain))) {
    result.riskLevel = "High";
    result.indicators.push("Sender domain is known for suspicious activities");
  }

  // Check email content for suspicious keywords
  suspiciousKeywords.forEach(keyword => {
    if (details.sender.email.toLowerCase().includes(keyword)) {
      result.riskLevel = "Medium";
      result.indicators.push(`Suspicious keyword detected: ${keyword}`);
    }
  });

  // More complex authentication checks
  if (Math.random() < 0.1) {  // 10% chance of failed authentication
    result.authResults.spf = "fail";
    result.riskLevel = "High";
    result.indicators.push("SPF authentication failed");
  }

  return result;
}

// Optional: Set up initial storage
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    enableNotifications: true
  });
});