document.addEventListener('DOMContentLoaded', function() {
  const statusElement = document.getElementById('status');
  const toggleDetailsButton = document.getElementById('toggle-details');
  const detailsSection = document.getElementById('details-section');
  
  // Initialize details section
  detailsSection.style.display = 'none';
  toggleDetailsButton.style.display = 'none';

  // Toggle details functionality
  toggleDetailsButton.addEventListener('click', function() {
    if (detailsSection.style.display === 'none') {
      detailsSection.style.display = 'block';
      toggleDetailsButton.textContent = 'Hide Details';
    } else {
      detailsSection.style.display = 'none';
      toggleDetailsButton.textContent = 'Show Details';
    }
  });

  // Listen for analysis updates
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "UPDATE_POPUP") {
      updatePopupWithAnalysis(message.result);
    }
  });

  // Load saved notification setting
  chrome.storage.local.get('enableNotifications', (data) => {
    document.getElementById('enable-notifications').checked = 
      data.enableNotifications !== false;
  });

  // Save notification setting
  document.getElementById('enable-notifications').addEventListener('change', (e) => {
    chrome.storage.local.set({
      enableNotifications: e.target.checked
    });
  });
});

function updatePopupWithAnalysis(result) {
  const statusElement = document.getElementById('status');
  const toggleDetailsButton = document.getElementById('toggle-details');
  const detailsSection = document.getElementById('details-section');

  // Reset display
  statusElement.className = 'status';
  detailsSection.style.display = 'none';
  toggleDetailsButton.style.display = 'block';
  toggleDetailsButton.textContent = 'Show Details';

  // Set risk level status
  if (result.riskLevel === "High") {
    statusElement.classList.add('danger');
    statusElement.textContent = '⚠️ High Risk: Potential email spoofing detected!';
  } else if (result.riskLevel === "Medium") {
    statusElement.classList.add('warning');
    statusElement.textContent = '⚠️ Medium Risk: Some suspicious indicators found';
  } else {
    statusElement.classList.add('safe');
    statusElement.textContent = '✓ Low Risk: Email appears legitimate';
  }

  // Update authentication results
  document.getElementById('spf-status').textContent = result.authResults.spf;
  document.getElementById('spf-status').style.color = 
    result.authResults.spf === 'pass' ? 'green' : 'red';

  document.getElementById('dkim-status').textContent = result.authResults.dkim;
  document.getElementById('dkim-status').style.color = 
    result.authResults.dkim === 'pass' ? 'green' : 'red';

  document.getElementById('dmarc-status').textContent = result.authResults.dmarc;
  document.getElementById('dmarc-status').style.color = 
    result.authResults.dmarc === 'pass' ? 'green' : 'red';

  // Update issues list
  const issuesList = document.getElementById('issues-list');
  issuesList.innerHTML = '';
  
  if (result.indicators && result.indicators.length > 0) {
    result.indicators.forEach(indicator => {
      const li = document.createElement('li');
      li.textContent = indicator;
      issuesList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'No issues detected';
    issuesList.appendChild(li);
  }
}