// Email platform-specific selectors
const EMAIL_PLATFORMS = {
  gmail: {
    emailContainer: '.a3s, .h7',
    senderSelector: '.gD',
    emailBodySelector: '.a3s'
  },
  outlook: {
    emailContainer: '.ReadingPaneContainer',
    senderSelector: '.addressLine',
    emailBodySelector: '.ReadingPaneContainer'
  },
  yahoo: {
    emailContainer: '.message-content-wrapper',
    senderSelector: '.from',
    emailBodySelector: '.message-content-wrapper'
  }
};

// Mutation observer configuration
const config = { 
  childList: true, 
  subtree: true 
};

let currentEmailId = null;

function detectEmailPlatform() {
  for (const [platform, selectors] of Object.entries(EMAIL_PLATFORMS)) {
    if (document.querySelector(selectors.emailContainer)) {
      return platform;
    }
  }
  return null;
}

function extractEmailDetails(platform) {
  const selectors = EMAIL_PLATFORMS[platform];
  
  const senderElement = document.querySelector(selectors.senderSelector);
  const emailContainer = document.querySelector(selectors.emailContainer);
  
  if (!senderElement || !emailContainer) return null;

  const senderText = senderElement.textContent || "";
  const emailMatch = senderText.match(/[\w\.-]+@[\w\.-]+/);
  const senderEmail = emailMatch ? emailMatch[0] : "";
  const senderName = senderText.replace(senderEmail, '').trim();

  return {
    sender: {
      name: senderName,
      email: senderEmail
    },
    platform: platform
  };
}

function generateEmailId(details) {
  if (!details) return null;
  return `${details.platform}-${details.sender.email}-${Date.now()}`;
}

function analyzeEmail(platform) {
  const emailDetails = extractEmailDetails(platform);
  if (!emailDetails) return;

  const emailId = generateEmailId(emailDetails);
  if (emailId === currentEmailId) return;

  currentEmailId = emailId;

  // Send message to background script for analysis
  chrome.runtime.sendMessage({
    type: "ANALYZE_HEADERS",
    details: {
      sender: emailDetails.sender,
      platform: platform
    }
  }, response => {
    if (response) {
      // Update popup with analysis results
      chrome.runtime.sendMessage({
        type: "UPDATE_POPUP",
        result: response
      });
    }
  });
}

function checkForOpenEmail() {
  const platform = detectEmailPlatform();
  if (platform) {
    analyzeEmail(platform);
  }
}

// Create and start observer
const observer = new MutationObserver(function(mutationsList, observer) {
  checkForOpenEmail();
});

// Start observing the document
observer.observe(document.body, config);

// Initial check
setTimeout(checkForOpenEmail, 1000);