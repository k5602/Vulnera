// HTML Report Generator for Vulnera
function generateHTMLReport(data, filename = "unknown") {
  const meta = data?.metadata || {};
  const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const sev = meta.severity_breakdown || { critical: 0, high: 0, medium: 0, low: 0 };
  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const getSeverityColor = (severity) => {
    const s = String(severity || "").toLowerCase();
    if (s === "critical") return "#dc2626"; // red-600
    if (s === "high") return "#ea580c"; // orange-600
    if (s === "medium") return "#d97706"; // amber-600
    return "#6b7280"; // gray-500
  };

  const getSeverityBg = (severity) => {
    const s = String(severity || "").toLowerCase();
    if (s === "critical") return "#fef2f2"; // red-50
    if (s === "high") return "#fff7ed"; // orange-50
    if (s === "medium") return "#fffbeb"; // amber-50
    return "#f9fafb"; // gray-50
  };

  const vulnerabilityCards = vulns.map(v => `
    <div class="vulnerability-card" style="border-left: 4px solid ${getSeverityColor(v.severity)}; background: ${getSeverityBg(v.severity)};">
      <div class="vulnerability-header">
        <span class="severity-badge" style="background: ${getSeverityColor(v.severity)};">${v.severity}</span>
        <h3 class="vulnerability-title">${escapeHtml(v.id)}</h3>
      </div>
      <p class="vulnerability-summary">${escapeHtml(v.summary || "")}</p>
      ${v.description ? `<p class="vulnerability-description">${escapeHtml(v.description)}</p>` : ""}

      ${Array.isArray(v.affected_packages) && v.affected_packages.length ? `
        <div class="affected-packages">
          <h4>Affected Packages:</h4>
          <div class="packages-grid">
            ${v.affected_packages.map(p => `
              <div class="package-item">
                <strong>${escapeHtml(p.name)}</strong> v${escapeHtml(p.version)}
                <span class="ecosystem">(${escapeHtml(p.ecosystem)})</span>
              </div>
            `).join("")}
          </div>
        </div>
      ` : ""}

      ${Array.isArray(v.references) && v.references.length ? `
        <div class="references">
          <h4>References:</h4>
          <ul>
            ${v.references.map(r => `<li><a href="${encodeURI(r)}" target="_blank">${escapeHtml(r)}</a></li>`).join("")}
          </ul>
        </div>
      ` : ""}
    </div>
  `).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnera Security Report - ${escapeHtml(filename)}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #374151;
            background: #f8fafc;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 1rem;
        }

        .header .filename {
            background: rgba(255, 255, 255, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            display: inline-block;
            font-family: 'Monaco', 'Consolas', monospace;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            text-align: center;
            border: 1px solid #e5e7eb;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #6b7280;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-summary {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }

        .severity-bars {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .severity-bar {
            text-align: center;
        }

        .severity-bar-fill {
            height: 8px;
            border-radius: 4px;
            margin: 0.5rem 0;
        }

        .vulnerabilities-section {
            margin-top: 2rem;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: #1f2937;
        }

        .vulnerability-card {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            border: 1px solid #e5e7eb;
        }

        .vulnerability-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .severity-badge {
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .vulnerability-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #1f2937;
        }

        .vulnerability-summary {
            font-size: 1.1rem;
            margin-bottom: 1rem;
            color: #4b5563;
        }

        .vulnerability-description {
            margin-bottom: 1.5rem;
            color: #6b7280;
        }

        .affected-packages, .references {
            margin-top: 1.5rem;
        }

        .affected-packages h4, .references h4 {
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: #374151;
        }

        .packages-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 0.5rem;
        }

        .package-item {
            background: #f9fafb;
            padding: 0.75rem;
            border-radius: 6px;
            border: 1px solid #e5e7eb;
        }

        .ecosystem {
            color: #6b7280;
            font-size: 0.875rem;
        }

        .references ul {
            list-style: none;
        }

        .references li {
            margin-bottom: 0.5rem;
        }

        .references a {
            color: #3b82f6;
            text-decoration: none;
            word-break: break-all;
        }

        .references a:hover {
            text-decoration: underline;
        }

        .no-vulnerabilities {
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            color: #065f46;
            padding: 2rem;
            border-radius: 12px;
            text-align: center;
            font-size: 1.1rem;
        }

        .footer {
            margin-top: 3rem;
            padding: 2rem;
            text-align: center;
            color: #6b7280;
            border-top: 1px solid #e5e7eb;
        }

        .metadata {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-top: 2rem;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .metadata-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #f3f4f6;
        }

        .metadata-item:last-child {
            border-bottom: none;
        }

        @media print {
            body { background: white; }
            .container { padding: 1rem; }
            .vulnerability-card { break-inside: avoid; }
        }

        @media (max-width: 768px) {
            .header h1 { font-size: 2rem; }
            .container { padding: 1rem; }
            .stat-card { padding: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Vulnera Security Report</h1>
            <p class="subtitle">Comprehensive Vulnerability Analysis</p>
            <div class="filename">${escapeHtml(filename)}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: #3b82f6;">${meta.total_packages ?? "-"}</div>
                <div class="stat-label">Total Packages</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ef4444;">${meta.total_vulnerabilities ?? vulns.length}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #f59e0b;">${meta.vulnerable_packages ?? "-"}</div>
                <div class="stat-label">Vulnerable Packages</div>
            </div>
        </div>

        <div class="severity-summary">
            <h2 class="section-title">Severity Breakdown</h2>
            <div class="severity-bars">
                <div class="severity-bar">
                    <div style="color: #dc2626; font-weight: 600;">Critical: ${sev.critical}</div>
                    <div class="severity-bar-fill" style="background: #dc2626; width: ${Math.max(10, (sev.critical / Math.max(1, meta.total_vulnerabilities || vulns.length)) * 100)}%;"></div>
                </div>
                <div class="severity-bar">
                    <div style="color: #ea580c; font-weight: 600;">High: ${sev.high}</div>
                    <div class="severity-bar-fill" style="background: #ea580c; width: ${Math.max(10, (sev.high / Math.max(1, meta.total_vulnerabilities || vulns.length)) * 100)}%;"></div>
                </div>
                <div class="severity-bar">
                    <div style="color: #d97706; font-weight: 600;">Medium: ${sev.medium}</div>
                    <div class="severity-bar-fill" style="background: #d97706; width: ${Math.max(10, (sev.medium / Math.max(1, meta.total_vulnerabilities || vulns.length)) * 100)}%;"></div>
                </div>
                <div class="severity-bar">
                    <div style="color: #6b7280; font-weight: 600;">Low: ${sev.low}</div>
                    <div class="severity-bar-fill" style="background: #6b7280; width: ${Math.max(10, (sev.low / Math.max(1, meta.total_vulnerabilities || vulns.length)) * 100)}%;"></div>
                </div>
            </div>
        </div>

        <div class="vulnerabilities-section">
            <h2 class="section-title">
                ${vulns.length > 0 ? `Vulnerability Details (${vulns.length})` : 'No Vulnerabilities Found'}
            </h2>

            ${vulns.length > 0 ? vulnerabilityCards : `
                <div class="no-vulnerabilities">
                    <h3>🎉 Great News!</h3>
                    <p>No known vulnerabilities were found in your dependencies.</p>
                    <p>Your project appears to be secure based on current vulnerability databases.</p>
                </div>
            `}
        </div>

        <div class="metadata">
            <h3 class="section-title">Analysis Details</h3>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span>Report Generated:</span>
                    <strong>${reportDate}</strong>
                </div>
                <div class="metadata-item">
                    <span>Analysis Duration:</span>
                    <strong>${meta.analysis_duration_ms || 0}ms</strong>
                </div>
                <div class="metadata-item">
                    <span>Sources Queried:</span>
                    <strong>${(meta.sources_queried || ['OSV', 'NVD', 'GHSA']).join(', ')}</strong>
                </div>
                <div class="metadata-item">
                    <span>Report ID:</span>
                    <strong>${data.id || 'N/A'}</strong>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by <strong>Vulnera</strong> - Comprehensive Vulnerability Analysis Platform</p>
            <p>Report Date: ${reportDate}</p>
        </div>
    </div>
</body>
</html>`;
}

// Helper function to escape HTML (already exists in main.js but duplicated here for completeness)
function escapeHtml(str) {
  return String(str || "").replace(
    /[&<>"']/g,
    (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c])
  );
}

// Export the function for use in main.js
export { generateHTMLReport };
