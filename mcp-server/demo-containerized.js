#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function demonstrateContainerizedScanning() {
  console.log('🐳 === CONTAINERIZED MCP SERVER LIVE SCANNING DEMO ===');
  console.log('🔍 Real-time vulnerability scanning using Trivy in container\n');

  try {
    // Connect to containerized MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "live-scanning-demo",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);
    console.log('✅ Connected to Containerized Copacetic MCP Server\n');

    // Check container status
    console.log('🏥 CONTAINER HEALTH CHECK:');
    const pingResult = await client.callTool({
      name: 'ping',
      arguments: {}
    });
    const ping = JSON.parse(pingResult.content[0].text);
    console.log(`   Server Status: ${ping.status}`);
    console.log(`   Server Version: ${ping.version}`);
    console.log(`   Timestamp: ${ping.timestamp}\n`);

    // Test 1: Scan a small image for quick results
    console.log('🔍 TEST 1: Scanning alpine:latest (lightweight image)');
    const alpineScanResult = await client.callTool({
      name: 'scan_image',
      arguments: {
        image: 'alpine:latest',
        format: 'json'
      }
    });
    const alpineScan = JSON.parse(alpineScanResult.content[0].text);
    console.log(`   Scan ID: ${alpineScan.scan_id}`);
    console.log(`   Status: ${alpineScan.status}`);
    console.log(`   Image: ${alpineScan.image}`);
    console.log(`   Scanner: ${alpineScan.scanner_type}\n`);

    // Show nginx vulnerability summary from cached results
    console.log('📊 TEST 2: nginx:1.27.0 Vulnerability Summary (from cache)');
    const summaryResult = await client.callTool({
      name: 'get_vulnerability_summary',
      arguments: { image: 'nginx:1.27.0' }
    });
    const summary = JSON.parse(summaryResult.content[0].text);

    console.log('   📈 Security Analysis Results:');
    console.log(`      Total Vulnerabilities: ${summary.total_vulnerabilities}`);
    console.log(`      🔴 Critical: ${summary.severity_breakdown.CRITICAL}`);
    console.log(`      🟠 High: ${summary.severity_breakdown.HIGH}`);
    console.log(`      🟡 Medium: ${summary.severity_breakdown.MEDIUM}`);
    console.log(`      🟢 Low: ${summary.severity_breakdown.LOW}`);
    console.log(`      📦 Affected Packages: ${summary.affected_packages.length}`);

    // Show some critical packages
    console.log('   \n🚨 Some affected critical packages:');
    summary.affected_packages.slice(0, 10).forEach(pkg => {
      console.log(`      • ${pkg}`);
    });
    console.log(`      ... and ${summary.affected_packages.length - 10} more packages\n`);

    // Test detailed scan results
    console.log('📋 TEST 3: Detailed Scan Results Analysis');
    const detailsResult = await client.callTool({
      name: 'get_scan_results',
      arguments: { image: 'nginx:1.27.0' }
    });
    const details = JSON.parse(detailsResult.content[0].text);

    if (!details.error) {
      console.log(`   ✅ Full scan data retrieved`);
      console.log(`   📁 Scan file: ${details.scan_file}`);
      console.log(`   📊 Result categories: ${details.results.Results?.length || 0}`);

      if (details.results.Results && details.results.Results[0]) {
        const firstResult = details.results.Results[0];
        console.log(`   🎯 Target: ${firstResult.Target || 'Container filesystem'}`);
        console.log(`   📝 Type: ${firstResult.Type || 'Package vulnerabilities'}`);
        console.log(`   🔢 Vulnerabilities: ${firstResult.Vulnerabilities?.length || 0}`);
      }
    }

    console.log('\n🔧 TEST 4: Remediation Workflow');
    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.27.0',
        output_tag: 'nginx:1.27.0-containerized-patched'
      }
    });
    const remediation = JSON.parse(remediationResult.content[0].text);
    console.log(`   🆔 Remediation ID: ${remediation.remediation_id}`);
    console.log(`   📊 Status: ${remediation.status}`);
    console.log(`   🏷️  Output Tag: ${remediation.output_image}`);
    console.log(`   ⚙️  Strategy: ${remediation.patch_strategy}`);

    console.log('\n🎉 === CONTAINERIZED SCANNING DEMO COMPLETE ===');
    console.log('✅ Successfully demonstrated:');
    console.log('   • Containerized MCP server deployment');
    console.log('   • Real-time vulnerability scanning with Trivy');
    console.log('   • Comprehensive vulnerability analysis');
    console.log('   • Automated remediation workflow');
    console.log('   • Multi-image scanning capabilities');
    console.log();
    console.log('🐳 Container Benefits:');
    console.log('   • Isolated execution environment');
    console.log('   • Consistent dependency management');
    console.log('   • Easy deployment and scaling');
    console.log('   • Built-in health monitoring');
    console.log('   • Container-to-container scanning');

    await client.close();

  } catch (error) {
    console.error('❌ Containerized demo failed:', error.message);
    process.exit(1);
  }
}

demonstrateContainerizedScanning();
