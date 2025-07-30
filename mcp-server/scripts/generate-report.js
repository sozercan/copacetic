#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');
const fs = require('fs');

async function generateSecurityReport() {
  console.log('📊 Generating comprehensive security report...\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "vscode-report-generator",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);

    // Get workspace scan results
    const workspaceScanFile = getLatestWorkspaceScan();
    if (!workspaceScanFile) {
      console.log('⚠️  No workspace scan results found. Run "Scan Current Workspace Images" first.');
      return;
    }

    const workspaceScan = JSON.parse(fs.readFileSync(workspaceScanFile, 'utf8'));

    console.log('📋 Generating detailed analysis for each image...\n');

    const detailedReports = [];

    for (const result of workspaceScan.results) {
      if (result.error) continue;

      console.log(`🔍 Analyzing ${result.image}...`);

      try {
        // Get detailed vulnerability report
        const summaryResult = await client.callTool({
          name: 'get_vulnerability_summary',
          arguments: { image: result.image }
        });

        const summary = JSON.parse(summaryResult.content[0].text);

        // Get remediation recommendations
        const remediationResult = await client.callTool({
          name: 'get_remediation_recommendations',
          arguments: { image: result.image }
        });

        const recommendations = JSON.parse(remediationResult.content[0].text);

        detailedReports.push({
          image: result.image,
          summary,
          recommendations,
          analysis_time: new Date().toISOString()
        });

        console.log(`   ✅ Analysis complete`);

      } catch (error) {
        console.log(`   ❌ Analysis failed: ${error.message}`);
      }
    }

    // Generate comprehensive report
    const report = {
      generated_at: new Date().toISOString(),
      workspace_summary: workspaceScan,
      detailed_analysis: detailedReports,
      security_metrics: calculateSecurityMetrics(workspaceScan, detailedReports),
      recommendations: generateRecommendations(detailedReports)
    };

    // Save reports in multiple formats
    saveReport(report, 'json');
    saveReport(report, 'html');
    saveReport(report, 'markdown');

    await client.close();

    console.log('\n🎯 Security report generation complete!');
    console.log('📄 Reports generated:');
    console.log(`   • JSON: reports/security-report-${getDateString()}.json`);
    console.log(`   • HTML: reports/security-report-${getDateString()}.html`);
    console.log(`   • Markdown: reports/security-report-${getDateString()}.md`);

  } catch (error) {
    console.error('❌ Report generation failed:', error.message);
    process.exit(1);
  }
}

function getLatestWorkspaceScan() {
  if (!fs.existsSync('reports')) return null;

  const files = fs.readdirSync('reports')
    .filter(f => f.startsWith('workspace-scan-') && f.endsWith('.json'))
    .sort()
    .reverse();

  return files.length > 0 ? `reports/${files[0]}` : null;
}

function calculateSecurityMetrics(workspaceScan, detailedReports) {
  const totalVulns = workspaceScan.total_vulnerabilities;
  const criticalVulns = workspaceScan.severity_summary.CRITICAL;
  const highVulns = workspaceScan.severity_summary.HIGH;

  const riskScore = (criticalVulns * 10 + highVulns * 5) / Math.max(totalVulns, 1);

  return {
    total_images: workspaceScan.total_images,
    total_vulnerabilities: totalVulns,
    risk_score: Math.round(riskScore * 10) / 10,
    security_grade: getSecurityGrade(riskScore),
    high_priority_vulns: criticalVulns + highVulns,
    remediation_coverage: calculateRemediationCoverage(detailedReports)
  };
}

function getSecurityGrade(riskScore) {
  if (riskScore >= 8) return 'F';
  if (riskScore >= 6) return 'D';
  if (riskScore >= 4) return 'C';
  if (riskScore >= 2) return 'B';
  return 'A';
}

function calculateRemediationCoverage(reports) {
  if (reports.length === 0) return 0;

  const totalRecommendations = reports.reduce((sum, r) =>
    sum + (r.recommendations?.patches?.length || 0), 0);
  const totalVulns = reports.reduce((sum, r) =>
    sum + (r.summary?.total_vulnerabilities || 0), 0);

  return totalVulns > 0 ? Math.round((totalRecommendations / totalVulns) * 100) : 0;
}

function generateRecommendations(reports) {
  const recommendations = [];

  // Priority recommendations based on analysis
  const criticalImages = reports.filter(r =>
    (r.summary?.severity_breakdown?.CRITICAL || 0) > 0);

  if (criticalImages.length > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Immediate patching required',
      description: `${criticalImages.length} images contain critical vulnerabilities`,
      images: criticalImages.map(r => r.image)
    });
  }

  const outdatedImages = reports.filter(r =>
    r.recommendations?.upgrade_recommendations?.length > 0);

  if (outdatedImages.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      action: 'Update base images',
      description: `${outdatedImages.length} images use outdated base images`,
      images: outdatedImages.map(r => r.image)
    });
  }

  return recommendations;
}

function saveReport(report, format) {
  const dateString = getDateString();
  const filename = `security-report-${dateString}`;

  if (!fs.existsSync('reports')) {
    fs.mkdirSync('reports');
  }

  switch (format) {
    case 'json':
      fs.writeFileSync(`reports/${filename}.json`, JSON.stringify(report, null, 2));
      break;

    case 'html':
      const html = generateHTMLReport(report);
      fs.writeFileSync(`reports/${filename}.html`, html);
      break;

    case 'markdown':
      const markdown = generateMarkdownReport(report);
      fs.writeFileSync(`reports/${filename}.md`, markdown);
      break;
  }
}

function generateHTMLReport(report) {
  const metrics = report.security_metrics;

  return `<!DOCTYPE html>
<html>
<head>
    <title>Security Report - ${report.generated_at.split('T')[0]}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #e8f4fd; border-radius: 5px; }
        .critical { background: #ffebee; }
        .high { background: #fff3e0; }
        .medium { background: #f3e5f5; }
        .low { background: #e8f5e8; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Report</h1>
        <p>Generated: ${report.generated_at}</p>
        <p>Security Grade: <strong>${metrics.security_grade}</strong> (Risk Score: ${metrics.risk_score})</p>
    </div>

    <div class="metrics">
        <div class="metric">
            <h3>📦 Images Scanned</h3>
            <p>${metrics.total_images}</p>
        </div>
        <div class="metric">
            <h3>🚨 Total Vulnerabilities</h3>
            <p>${metrics.total_vulnerabilities}</p>
        </div>
        <div class="metric">
            <h3>⚠️ High Priority</h3>
            <p>${metrics.high_priority_vulns}</p>
        </div>
        <div class="metric">
            <h3>🔧 Remediation Coverage</h3>
            <p>${metrics.remediation_coverage}%</p>
        </div>
    </div>

    <h2>📊 Vulnerability Breakdown</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr class="critical"><td>Critical</td><td>${report.workspace_summary.severity_summary.CRITICAL}</td></tr>
        <tr class="high"><td>High</td><td>${report.workspace_summary.severity_summary.HIGH}</td></tr>
        <tr class="medium"><td>Medium</td><td>${report.workspace_summary.severity_summary.MEDIUM}</td></tr>
        <tr class="low"><td>Low</td><td>${report.workspace_summary.severity_summary.LOW}</td></tr>
    </table>

    <h2>🎯 Recommendations</h2>
    ${report.recommendations.map(rec => `
        <div class="metric ${rec.priority.toLowerCase()}">
            <h4>${rec.action}</h4>
            <p>${rec.description}</p>
            <small>Priority: ${rec.priority}</small>
        </div>
    `).join('')}
</body>
</html>`;
}

function generateMarkdownReport(report) {
  const metrics = report.security_metrics;

  return `# 🛡️ Security Report

**Generated:** ${report.generated_at}
**Security Grade:** ${metrics.security_grade} (Risk Score: ${metrics.risk_score})

## 📊 Summary Metrics

| Metric | Value |
|--------|-------|
| 📦 Images Scanned | ${metrics.total_images} |
| 🚨 Total Vulnerabilities | ${metrics.total_vulnerabilities} |
| ⚠️ High Priority | ${metrics.high_priority_vulns} |
| 🔧 Remediation Coverage | ${metrics.remediation_coverage}% |

## 🔍 Vulnerability Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${report.workspace_summary.severity_summary.CRITICAL} |
| 🟠 High | ${report.workspace_summary.severity_summary.HIGH} |
| 🟡 Medium | ${report.workspace_summary.severity_summary.MEDIUM} |
| 🟢 Low | ${report.workspace_summary.severity_summary.LOW} |

## 🎯 Recommendations

${report.recommendations.map(rec => `
### ${rec.action}
- **Priority:** ${rec.priority}
- **Description:** ${rec.description}
- **Affected Images:** ${rec.images.length}
`).join('')}

## 📋 Detailed Analysis

${report.detailed_analysis.map(analysis => `
### ${analysis.image}
- **Total Vulnerabilities:** ${analysis.summary.total_vulnerabilities}
- **Affected Packages:** ${analysis.summary.affected_packages.length}
- **Remediation Available:** ${analysis.recommendations.patches?.length || 0} patches
`).join('')}
`;
}

function getDateString() {
  return new Date().toISOString().split('T')[0];
}

generateSecurityReport();
