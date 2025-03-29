function checkEmailSpoofing(emailHeaders) {
    let suspiciousHeaders = ["Return-Path", "Received-SPF", "Authentication-Results"];
    let spoofed = false;

    suspiciousHeaders.forEach(header => {
        if (!emailHeaders.includes(header)) {
            spoofed = true;
        }
    });

    if (spoofed) {
        alert("⚠️ Warning: This email may be spoofed!");
    } else {
        console.log("✅ Email headers verified.");
    }
}

// Example usage
let fakeEmailHeaders = "From: fake@paypal.com\nReceived: from hacker.com\n";
checkEmailSpoofing(fakeEmailHeaders);
