#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function testMCPServer() {
  console.log('🚀 Testing MCP Server with SSE transport...');

  try {
    // Create SSE transport pointing to our server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));

    // Create MCP client
    const client = new Client(
      {
        name: "nginx-patcher-client",
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

    // List available tools
    console.log('\n📋 Listing available tools...');
    const toolsResult = await client.listTools();
    console.log(`Found ${toolsResult.tools.length} tools:`);
    toolsResult.tools.forEach(tool => {
      console.log(`  - ${tool.name}: ${tool.description}`);
    });

    // Test ping tool
    console.log('\n🏓 Testing ping tool...');
    const pingResult = await client.callTool({
      name: 'ping',
      arguments: {}
    });
    console.log('Ping result:', pingResult.content[0].text);

    // Scan nginx:1.27.0 image
    console.log('\n🔍 Scanning nginx:1.27.0 for vulnerabilities...');
    const scanResult = await client.callTool({
      name: 'scan_image',
      arguments: {
        image: 'nginx:1.27.0',
        format: 'json'
      }
    });
    console.log('Scan result:', scanResult.content[0].text);

    // Get vulnerability summary
    console.log('\n📈 Getting vulnerability summary...');
    const summaryResult = await client.callTool({
      name: 'get_vulnerability_summary',
      arguments: {
        image: 'nginx:1.27.0'
      }
    });
    console.log('Summary result:', summaryResult.content[0].text);

    // Trigger remediation
    console.log('\n🔧 Triggering remediation...');
    const remediationResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.27.0',
        output_tag: 'nginx:1.27.0-patched'
      }
    });
    console.log('Remediation result:', remediationResult.content[0].text);

    console.log('\n✅ End-to-end nginx patching workflow completed via MCP server!');

    // Close connection
    await client.close();

  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

testMCPServer();
