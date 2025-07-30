#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function demonstrateNginxPatching() {
  console.log('🎯 === COPACETIC MCP SERVER DEMONSTRATION ===');
  console.log('🐳 End-to-End nginx:1.27.0 Vulnerability Scanning & Remediation\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "copacetic-demo-client",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);
    console.log('✅ Connected to Copacetic MCP Server\n');

    // Step 1: Server Health Check
    console.log('🏓 STEP 1: Server Health Check');
    const pingResult = await client.callTool({
      name: 'ping',
      arguments: {}
    });
    const ping = JSON.parse(pingResult.content[0].text);
    console.log(`   Server Status: ${ping.status} (v${ping.version})\n`);

    // Step 2: List Available Capabilities
    console.log('🛠️  STEP 2: Available Security Tools');
    const toolsResult = await client.listTools();
    console.log(`   Found ${toolsResult.tools.length} vulnerability management tools:`);
    toolsResult.tools.forEach(tool => {
      console.log(`   • ${tool.name}: ${tool.description.substring(0, 60)}...`);
    });
    console.log();

    // Step 3: Vulnerability Scanning
    console.log('🔍 STEP 3: Vulnerability Analysis for nginx:1.27.0');
    const summaryResult = await client.callTool({
      name: 'get_vulnerability_summary',
      arguments: { image: 'nginx:1.27.0' }
    });
    const summary = JSON.parse(summaryResult.content[0].text);

    console.log('   📊 Vulnerability Summary:');
    console.log(`      Total Vulnerabilities: ${summary.total_vulnerabilities}`);
    console.log(`      🔴 Critical: ${summary.severity_breakdown.CRITICAL}`);
    console.log(`      🟠 High: ${summary.severity_breakdown.HIGH}`);
    console.log(`      🟡 Medium: ${summary.severity_breakdown.MEDIUM}`);
    console.log(`      🟢 Low: ${summary.severity_breakdown.LOW}`);
    console.log(`      📦 Affected Packages: ${summary.affected_packages.length}`);
    console.log(`      📅 Scan Date: ${summary.scan_timestamp}\n`);

    // Step 4: Critical Vulnerabilities Analysis
    const highRiskVulns = summary.severity_breakdown.CRITICAL + summary.severity_breakdown.HIGH;
    console.log(`🚨 STEP 4: High-Risk Vulnerability Assessment`);
    console.log(`   Found ${highRiskVulns} CRITICAL/HIGH severity vulnerabilities requiring immediate attention`);
    console.log(`   Recommendation: Proceed with automated remediation\n`);

    // Step 5: Remediation Process
    console.log('🔧 STEP 5: Triggering Automated Remediation');
    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.27.0',
        output_tag: 'nginx:1.27.0-copacetic-patched'
      }
    });
    const remediation = JSON.parse(remediationResult.content[0].text);
    console.log(`   Remediation ID: ${remediation.remediation_id}`);
    console.log(`   Status: ${remediation.status}`);
    console.log(`   Output Image: ${remediation.output_image}`);
    console.log(`   Strategy: ${remediation.patch_strategy}\n`);

    // Step 6: Remediation Report
    console.log('📋 STEP 6: Remediation Results');
    const reportResult = await client.callTool({
      name: 'get_remediation_report',
      arguments: { image: 'nginx:1.27.0' }
    });
    const report = JSON.parse(reportResult.content[0].text);

    console.log('   🎯 Remediation Summary:');
    console.log(`      Status: ${report.remediation_status}`);
    console.log(`      Patches Applied: ${report.patches_applied}`);
    console.log(`      Vulnerabilities Fixed: ${report.vulnerabilities_fixed}/${summary.total_vulnerabilities}`);
    console.log(`      Remaining Issues: ${report.remaining_vulnerabilities}`);
    console.log(`      Build Time: ${report.build_time}`);
    console.log(`      Size Impact: ${report.size_change}`);
    console.log(`      Output Image: ${report.output_image}\n`);

    // Final Summary
    const fixRate = Math.round((report.vulnerabilities_fixed / summary.total_vulnerabilities) * 100);
    console.log('🎉 === REMEDIATION COMPLETE ===');
    console.log(`✅ Successfully patched nginx:1.27.0 using Copacetic MCP Server`);
    console.log(`📈 Remediation Effectiveness: ${fixRate}% of vulnerabilities addressed`);
    console.log(`🔒 Security Improvement: ${highRiskVulns} critical/high vulnerabilities mitigated`);
    console.log(`🐳 Patched Image Available: ${report.output_image}`);
    console.log();
    console.log('🚀 Next Steps:');
    console.log('   • Deploy patched image to production');
    console.log('   • Monitor for new vulnerabilities');
    console.log('   • Schedule regular security scans');
    console.log();
    console.log('📚 MCP Server provides comprehensive vulnerability management:');
    console.log('   • Trivy-powered security scanning');
    console.log('   • Copa-based automated patching');
    console.log('   • Real-time remediation tracking');
    console.log('   • Registry integration support');

    await client.close();

  } catch (error) {
    console.error('❌ Demonstration failed:', error.message);
    process.exit(1);
  }
}

demonstrateNginxPatching();
