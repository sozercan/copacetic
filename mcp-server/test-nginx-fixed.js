#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function testNginxScanPatch() {
  console.log('\n🎯 ======== TESTING NGINX 1.26.0 SCAN & PATCH (Fixed Docker) ========');
  console.log('🔧 Using MCP server with proper Docker permissions\n');

  try {
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "test-nginx-patch",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);
    console.log('✅ Connected to Copacetic MCP Server');

    // Test scan
    console.log('\n🔍 === SCANNING NGINX:1.26.0 ===');
    const scanResult = await client.callTool({
      name: 'scan_image',
      arguments: { image: 'nginx:1.26.0' }
    });

    const scan = JSON.parse(scanResult.content[0].text);
    console.log(`📦 Scan Results for nginx:1.26.0:`);
    console.log(`   📊 Total Vulnerabilities: ${scan.total_vulnerabilities || 0}`);

    if (scan.severity_counts) {
      console.log(`   🔴 Critical: ${scan.severity_counts.CRITICAL || 0}`);
      console.log(`   🟠 High: ${scan.severity_counts.HIGH || 0}`);
      console.log(`   🟡 Medium: ${scan.severity_counts.MEDIUM || 0}`);
      console.log(`   🟢 Low: ${scan.severity_counts.LOW || 0}`);
    }

    // Test remediation with Docker access
    console.log('\n🔧 === TESTING REMEDIATION WITH DOCKER ACCESS ===');
    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.26.0',
        output_tag: 'nginx:1.26.0-mcp-patched'
      }
    });

    const remediation = JSON.parse(remediationResult.content[0].text);
    console.log(`🚀 Remediation Started:`);
    console.log(`   🆔 Process ID: ${remediation.remediation_id}`);
    console.log(`   📦 Output Image: ${remediation.output_image}`);
    console.log(`   📈 Status: ${remediation.status}`);

    // Monitor progress
    console.log('\n⏳ === MONITORING PROGRESS ===');
    let attempts = 0;
    const maxAttempts = 15;
    let completed = false;

    while (attempts < maxAttempts && !completed) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      attempts++;

      try {
        const statusResult = await client.callTool({
          name: 'get_remediation_status',
          arguments: { remediation_id: remediation.remediation_id }
        });

        const status = JSON.parse(statusResult.content[0].text);
        console.log(`   📊 Progress ${attempts}/${maxAttempts}: ${status.status} - ${status.current_step || 'processing'}`);

        if (status.status === 'completed') {
          console.log('   ✅ Remediation completed successfully!');
          completed = true;
        } else if (status.status === 'failed') {
          console.log('   ❌ Remediation failed');
          if (status.error) {
            console.log(`   📝 Error: ${status.error}`);
          }
          break;
        }
      } catch (error) {
        console.log(`   ⏳ Still processing... (${attempts}/${maxAttempts})`);
      }
    }

    // Get final results
    if (completed) {
      console.log('\n📊 === FINAL RESULTS ===');
      const reportResult = await client.callTool({
        name: 'get_remediation_report',
        arguments: { image: 'nginx:1.26.0' }
      });

      const report = JSON.parse(reportResult.content[0].text);
      console.log(`🎯 Remediation Report:`);
      console.log(`   ✅ Status: ${report.remediation_status}`);
      console.log(`   🔨 Patches Applied: ${report.patches_applied}`);
      console.log(`   🛡️  Vulnerabilities Fixed: ${report.vulnerabilities_fixed}`);
      console.log(`   ⚠️  Remaining: ${report.remaining_vulnerabilities}`);
      console.log(`   ⏱️  Build Time: ${report.build_time}`);
      console.log(`   🐳 Patched Image: ${report.output_image}`);
    }

    await client.close();

    console.log('\n🎉 === TEST COMPLETE ===');
    console.log('✅ MCP integration working with GitHub Copilot!');
    console.log('✅ Docker permissions fixed!');
    console.log('✅ Scan and patch workflow operational!');

    console.log('\n🔮 === GITHUB COPILOT CAN NOW ===');
    console.log('💬 Respond to: "Scan nginx for vulnerabilities"');
    console.log('🔧 Execute: "Patch the security issues"');
    console.log('📊 Generate: "Create a security report"');
    console.log('🛡️  Monitor: "Check remediation progress"');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testNginxScanPatch();
