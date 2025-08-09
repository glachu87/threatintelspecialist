async function showFeed(feedType) {
  const container = document.getElementById('feed-content');
  container.innerHTML = `<p>Loading ${feedType} feed...</p>`;

  if (feedType === 'cisa') {
    const res = await fetch('/feeds/cisa/advisories.json');
    if (!res.ok) {
      container.innerHTML = `<p>Failed to load CISA advisories</p>`;
      return;
    }
    const data = await res.json();
    renderCisa(data, container);
  }
  else if (feedType === 'ncsc') {
    container.innerHTML = `<p>NCSC feed coming soon</p>`;
  }
  else if (feedType === 'virustotal') {
    container.innerHTML = `<p>VirusTotal feed coming soon</p>`;
  }
}

function renderCisa(data, container) {
  container.innerHTML = `<h2>CISA Cybersecurity Advisories</h2>`;

  // If your advisories.json contains full structured fields, adjust mapping here
  data.items.forEach(advisory => {
    container.innerHTML += `
      <div class="advisory-card">
        <h3>${advisory.title || 'No title'}</h3>
        <table class="advisory-table">
          <tr><th>Vendor</th><td>${advisory.vendor || 'N/A'}</td></tr>
          <tr><th>Affected Products</th><td>${advisory.affected_products || 'N/A'}</td></tr>
          <tr><th>Release Date</th><td>${advisory.published || 'N/A'}</td></tr>
          <tr><th>CVSS v4 Score</th><td>${advisory.cvss_v4 || 'N/A'}</td></tr>
          <tr><th>Executive Summary</th><td>${advisory.summary || 'N/A'}</td></tr>
          <tr><th>Risk Evaluation</th><td>${advisory.risk_evaluation || 'N/A'}</td></tr>
          <tr><th>Vulnerability Overview</th><td>${advisory.vulnerability_overview || 'N/A'}</td></tr>
          <tr><th>Mitigations</th><td>${advisory.mitigations || 'N/A'}</td></tr>
        </table>
      </div>
    `;
  });
}
