document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("checkDns").addEventListener("click", function () {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (tabs.length > 0) {
                let tabUrl = tabs[0].url;

                chrome.runtime.sendMessage({ action: "check_dns", url: tabUrl }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Error sending message:", chrome.runtime.lastError);
                    } else {
                        let statusMsg = document.getElementById("statusMessage");
                        statusMsg.innerText = response.status || "DNS check initiated!";
                        statusMsg.style.display = "block"; // Show the message

                        // Hide the message after 3 seconds
                        setTimeout(() => {
                            statusMsg.style.display = "none";
                        }, 3000);
                    }
                });
            }
        });
    });
    document.addEventListener("DOMContentLoaded", function () {
        // Check Email Spoofing
        document.getElementById("checkEmail").addEventListener("click", function () {
            chrome.runtime.sendMessage({ action: "check_email" }, (response) => {
                let statusMessage = document.getElementById("statusMessage");
                if (response && response.status) {
                    statusMessage.innerText = response.status;
                    statusMessage.style.display = "block";
    
                    setTimeout(() => {
                        statusMessage.style.display = "none";
                    }, 3000); // Hide message after 3 seconds
                }
            });
        });
    });
});    