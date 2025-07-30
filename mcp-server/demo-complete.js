#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForScanCompletion(client, image, maxWait = 120000) {
  console.log(`⏳ Waiting for scan of ${image} to complete...`);
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    try {
      const summaryResult = await client.callTool({
        name: 'get_vulnerability_summary',
        arguments: { image }
      });

      const summary = JSON.parse(summaryResult.content[0].text);
      if (!summary.error) {
        console.log(`✅ Scan completed for ${image}!`);
        return summary;
      }
    } catch (error) {
      // Scan not ready yet
    }

    await sleep(5000); // Wait 5 seconds before checking again
  }

  throw new Error(`Scan did not complete within ${maxWait/1000} seconds`);
}

async function runCompleteNginxWorkflow() {
  console.log('🚀 Complete nginx:1.27.0 patching workflow via MCP server...');

  try {
    // Create SSE transport pointing to our server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));

    // Create MCP client
    const client = new Client(
      {
        name: "nginx-patcher-workflow",
        version: "1.0.0",
      },
      {
        capabilities: {},
      }
    );

    // Connect to the server
    console.log('🔗 Connecting to MCP server...');
    await client.connect(transport);
    console.log('✅ Connected to MCP server!');

    // Step 1: List available tools
    console.log('\n📋 Step 1: Listing available tools...');
    const toolsResult = await client.listTools();
    console.log(`Found ${toolsResult.tools.length} tools available for vulnerability scanning and remediation`);

    // Step 2: Test server connectivity
    console.log('\n🏓 Step 2: Testing server connectivity...');
    const pingResult = await client.callTool({
      name: 'ping',
      arguments: {}
    });
    const pingData = JSON.parse(pingResult.content[0].text);
    console.log(`Server is healthy and running (version: ${pingData.version})`);

    // Step 3: Scan nginx:1.27.0 image
    console.log('\n🔍 Step 3: Initiating vulnerability scan for nginx:1.27.0...');
    const scanResult = await client.callTool({
      name: 'scan_image',
      arguments: {
        image: 'nginx:1.27.0',
        format: 'json'
      }
    });
    const scanData = JSON.parse(scanResult.content[0].text);
    console.log(`Scan initiated with ID: ${scanData.scan_id}`);

    // Step 4: Wait for scan completion and get vulnerability summary
    console.log('\n📊 Step 4: Waiting for scan completion and getting vulnerability summary...');
    const summary = await waitForScanCompletion(client, 'nginx:1.27.0');

    console.log(`\n📈 Vulnerability Summary for nginx:1.27.0:`);
    console.log(`  Total Vulnerabilities: ${summary.total_vulnerabilities}`);
    console.log(`  Critical: ${summary.severity_breakdown.CRITICAL}`);
    console.log(`  High: ${summary.severity_breakdown.HIGH}`);
    console.log(`  Medium: ${summary.severity_breakdown.MEDIUM}`);
    console.log(`  Low: ${summary.severity_breakdown.LOW}`);
    console.log(`  Affected Packages: ${summary.affected_packages.length}`);

    // Step 5: Get detailed scan results
    console.log('\n📋 Step 5: Retrieving detailed scan results...');
    const detailsResult = await client.callTool({
      name: 'get_scan_results',
      arguments: {
        image: 'nginx:1.27.0'
      }
    });
    const detailsData = JSON.parse(detailsResult.content[0].text);
    if (!detailsData.error) {
      console.log(`✅ Detailed scan results retrieved (${detailsData.results.Results?.length || 0} result categories)`);
    }

    // Step 6: Trigger remediation
    console.log('\n🔧 Step 6: Triggering image remediation...');
    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.27.0',
        output_tag: 'nginx:1.27.0-patched'
      }
    });
    const remediationData = JSON.parse(remediationResult.content[0].text);
    console.log(`Remediation initiated with ID: ${remediationData.remediation_id}`);
    console.log(`Output image will be: ${remediationData.output_image}`);

    // Step 7: Get remediation report
    console.log('\n📊 Step 7: Getting remediation report...');
    const reportResult = await client.callTool({
      name: 'get_remediation_report',
      arguments: {
        image: 'nginx:1.27.0'
      }
    });
    const reportData = JSON.parse(reportResult.content[0].text);
    console.log(`\n🎯 Remediation Report:`);
    console.log(`  Status: ${reportData.remediation_status}`);
    console.log(`  Patches Applied: ${reportData.patches_applied}`);
    console.log(`  Vulnerabilities Fixed: ${reportData.vulnerabilities_fixed}`);
    console.log(`  Remaining Vulnerabilities: ${reportData.remaining_vulnerabilities}`);
    console.log(`  Output Image: ${reportData.output_image}`);
    console.log(`  Build Time: ${reportData.build_time}`);
    console.log(`  Size Change: ${reportData.size_change}`);

    console.log('\n🎉 ✅ Complete end-to-end nginx:1.27.0 patching workflow completed successfully via MCP server!');
    console.log('\n📝 Summary:');
    console.log(`   • Scanned nginx:1.27.0 and found ${summary.total_vulnerabilities} vulnerabilities`);
    console.log(`   • Critical/High vulnerabilities: ${summary.severity_breakdown.CRITICAL + summary.severity_breakdown.HIGH}`);
    console.log(`   • Triggered automated remediation process`);
    console.log(`   • Generated patched image: nginx:1.27.0-patched`);
    console.log(`   • Fixed ${reportData.vulnerabilities_fixed} out of ${summary.total_vulnerabilities} vulnerabilities`);

    // Close connection
    await client.close();

  } catch (error) {
    console.error('❌ Error in workflow:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

runCompleteNginxWorkflow();
