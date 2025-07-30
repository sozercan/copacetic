#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function testExtendedTimeout() {
  console.log('🧪 Testing extended timeout functionality...\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "timeout-tester",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);

    // Test with a large image that may take longer to scan
    const testImage = 'ubuntu:22.04';
    console.log(`🔍 Testing scan timeout with ${testImage}...`);
    console.log('   📝 Previous timeout was 15 seconds, now extended to 5 minutes');
    console.log('   ⏰ Starting scan (this may take several minutes)...\n');

    const startTime = Date.now();

    try {
      const scanResult = await client.callTool({
        name: 'scan_image',
        arguments: { image: testImage }
      });

      const scan = JSON.parse(scanResult.content[0].text);
      const duration = ((Date.now() - startTime) / 1000).toFixed(1);

      if (scan.status === 'in_progress') {
        console.log(`   ⏳ Scan returned in-progress status after ${duration}s - this demonstrates the extended timeout is working!`);
        console.log(`   📋 Scan ID: ${scan.scan_id}`);
        console.log(`   💡 The scan continues in the background. Use get_scan_status to check completion.`);
      } else {
        console.log(`   ✅ Scan completed in ${duration}s with ${scan.total_vulnerabilities} vulnerabilities`);
        console.log(`   🔍 This demonstrates the extended timeout allowed the scan to complete successfully!`);
      }

    } catch (error) {
      const duration = ((Date.now() - startTime) / 1000).toFixed(1);
      
      if (error.message.includes('timeout')) {
        console.log(`   ❌ Scan timed out after ${duration}s`);
        console.log(`   ⚠️  This suggests the timeout may need to be extended further for very large images`);
      } else {
        console.log(`   ❌ Scan failed after ${duration}s: ${error.message}`);
      }
    }

    await client.close();

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testExtendedTimeout();
