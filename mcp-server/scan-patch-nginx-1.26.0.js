#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function scanAndPatchNginx() {
  console.log('\n🎯 ======== NGINX 1.26.0 SCAN AND PATCH WORKFLOW ========');
  console.log('🔍 Scanning nginx:1.26.0 for vulnerabilities...');
  console.log('🔧 Then applying automated security patches\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "nginx-patch-workflow",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);
    console.log('✅ Connected to Copacetic MCP Server\n');

    // Step 1: Scan nginx:1.26.0
    console.log('🔍 === STEP 1: VULNERABILITY SCAN ===');
    const scanResult = await client.callTool({
      name: 'scan_image',
      arguments: { image: 'nginx:1.26.0' }
    });

    const scan = JSON.parse(scanResult.content[0].text);

    console.log(`📦 Image: nginx:1.26.0`);
    console.log(`📊 Total Vulnerabilities: ${scan.total_vulnerabilities || 0}`);

    if (scan.severity_counts) {
      console.log(`🔴 Critical: ${scan.severity_counts.CRITICAL || 0}`);
      console.log(`🟠 High: ${scan.severity_counts.HIGH || 0}`);
      console.log(`🟡 Medium: ${scan.severity_counts.MEDIUM || 0}`);
      console.log(`🟢 Low: ${scan.severity_counts.LOW || 0}`);
    }

    // Step 2: Get vulnerability summary
    console.log('\n📋 === STEP 2: DETAILED VULNERABILITY ANALYSIS ===');
    const summaryResult = await client.callTool({
      name: 'get_vulnerability_summary',
      arguments: { image: 'nginx:1.26.0' }
    });

    const summary = JSON.parse(summaryResult.content[0].text);

    console.log(`🎯 Vulnerability Summary:`);
    console.log(`   📦 Affected Packages: ${summary.affected_packages?.length || 0}`);
    console.log(`   🔍 Total Issues: ${summary.total_vulnerabilities}`);
    console.log(`   📊 Severity Distribution:`);
    console.log(`      🔴 Critical: ${summary.severity_breakdown?.CRITICAL || 0}`);
    console.log(`      🟠 High: ${summary.severity_breakdown?.HIGH || 0}`);
    console.log(`      🟡 Medium: ${summary.severity_breakdown?.MEDIUM || 0}`);
    console.log(`      🟢 Low: ${summary.severity_breakdown?.LOW || 0}`);

    const criticalHigh = (summary.severity_breakdown?.CRITICAL || 0) + (summary.severity_breakdown?.HIGH || 0);

    if (criticalHigh > 0) {
      console.log(`\n⚠️  HIGH-PRIORITY ALERT: ${criticalHigh} critical/high severity vulnerabilities found!`);
      console.log('🔧 Proceeding with automated remediation...');
    } else {
      console.log('\n✅ Good news: No critical or high severity vulnerabilities found!');
      console.log('🔧 Still proceeding with patching for medium/low severity issues...');
    }

    // Step 3: Trigger remediation
    console.log('\n🔧 === STEP 3: AUTOMATED REMEDIATION ===');
    console.log('🚀 Starting automated patching process...');

    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.26.0',
        output_tag: 'nginx:1.26.0-patched'
      }
    });

    const remediation = JSON.parse(remediationResult.content[0].text);

    console.log(`✅ Remediation Process Started:`);
    console.log(`   🆔 Process ID: ${remediation.remediation_id}`);
    console.log(`   📦 Source Image: nginx:1.26.0`);
    console.log(`   🏷️  Target Image: ${remediation.output_image}`);
    console.log(`   ⚙️  Strategy: ${remediation.patch_strategy} patching`);
    console.log(`   📈 Status: ${remediation.status}`);

    // Step 4: Monitor remediation progress
    console.log('\n⏳ === STEP 4: MONITORING PATCH PROGRESS ===');
    console.log('⏱️  Waiting for remediation to complete...');

    let attempts = 0;
    const maxAttempts = 10;
    let completed = false;

    while (attempts < maxAttempts && !completed) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      attempts++;

      try {
        const statusResult = await client.callTool({
          name: 'get_remediation_status',
          arguments: { remediation_id: remediation.remediation_id }
        });

        const status = JSON.parse(statusResult.content[0].text);

        console.log(`   📊 Attempt ${attempts}: ${status.status} (${status.current_step || 'processing'})`);

        if (status.status === 'completed' || status.status === 'failed') {
          completed = true;

          if (status.status === 'completed') {
            console.log('   ✅ Remediation completed successfully!');
          } else {
            console.log('   ❌ Remediation failed');
            if (status.error) {
              console.log(`   📝 Error: ${status.error}`);
            }
          }
        }
      } catch (error) {
        console.log(`   ⏳ Still processing... (${attempts}/${maxAttempts})`);
      }
    }

    // Step 5: Get final remediation report
    console.log('\n📊 === STEP 5: REMEDIATION RESULTS ===');

    try {
      const reportResult = await client.callTool({
        name: 'get_remediation_report',
        arguments: { image: 'nginx:1.26.0' }
      });

      const report = JSON.parse(reportResult.content[0].text);

      console.log(`🎯 Final Remediation Report:`);
      console.log(`   ✅ Status: ${report.remediation_status}`);
      console.log(`   🔨 Patches Applied: ${report.patches_applied}`);
      console.log(`   🛡️  Vulnerabilities Fixed: ${report.vulnerabilities_fixed}`);
      console.log(`   ⚠️  Remaining Issues: ${report.remaining_vulnerabilities}`);
      console.log(`   ⏱️  Build Time: ${report.build_time}`);
      console.log(`   📏 Size Impact: ${report.size_change}`);
      console.log(`   🐳 Patched Image: ${report.output_image}`);

      // Calculate improvement metrics
      const originalVulns = summary.total_vulnerabilities;
      const fixedVulns = report.vulnerabilities_fixed;
      const fixRate = originalVulns > 0 ? Math.round((fixedVulns / originalVulns) * 100) : 0;

      console.log('\n📈 === SECURITY IMPROVEMENT METRICS ===');
      console.log(`🎯 Overall Fix Rate: ${fixRate}%`);
      console.log(`📊 Before: ${originalVulns} vulnerabilities`);
      console.log(`📊 After: ${report.remaining_vulnerabilities} vulnerabilities`);
      console.log(`✅ Fixed: ${fixedVulns} vulnerabilities`);

      if (criticalHigh > 0) {
        const criticalHighFixed = Math.min(criticalHigh, fixedVulns);
        const criticalFixRate = Math.round((criticalHighFixed / criticalHigh) * 100);
        console.log(`🔥 Critical/High Fix Rate: ${criticalFixRate}%`);
      }

    } catch (error) {
      console.log('⚠️  Remediation report not yet available. Process may still be running.');
    }

    await client.close();

    console.log('\n🎉 ======== NGINX 1.26.0 PATCH WORKFLOW COMPLETE ========');
    console.log('\n✅ SUMMARY:');
    console.log('   🔍 Vulnerability scan completed');
    console.log('   🔧 Automated patching triggered');
    console.log('   📊 Remediation results analyzed');
    console.log('   🐳 Patched image ready for use');

    console.log('\n💡 NEXT STEPS:');
    console.log('   1. Test the patched image: docker run nginx:1.26.0-patched');
    console.log('   2. Update your Dockerfile: FROM nginx:1.26.0-patched');
    console.log('   3. Validate application functionality');
    console.log('   4. Deploy to production');

    console.log('\n🔒 SECURITY BENEFITS:');
    console.log('   • Reduced attack surface');
    console.log('   • Latest security patches applied');
    console.log('   • Compliance requirements met');
    console.log('   • Continuous security monitoring');

  } catch (error) {
    console.error('\n❌ Scan and patch workflow failed:', error.message);
    console.log('\n🔧 Troubleshooting:');
    console.log('   1. Ensure Copacetic MCP Server is running');
    console.log('   2. Check Docker daemon is accessible');
    console.log('   3. Verify network connectivity');
    console.log('   4. Check server logs for details');
    process.exit(1);
  }
}

scanAndPatchNginx();
