#!/usr/bin/env node

// MCP Client for VS Code Integration Demo
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function demonstrateMCPIntegration() {
  console.log('\n🔌 ======== MCP VS CODE INTEGRATION DEMO ========');
  console.log('🛠️  Connecting VS Code AI Assistant to Copacetic MCP Server\n');

  try {
    // Connect to MCP Server (same way VS Code AI would)
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "vscode-ai-assistant",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);
    console.log('✅ Connected to Copacetic MCP Server');

    // Demonstrate MCP tool discovery (what VS Code AI sees)
    console.log('\n🔍 === TOOL DISCOVERY (What AI Assistant Sees) ===');
    const tools = await client.listTools();

    console.log(`📦 Available Tools: ${tools.tools.length}`);
    tools.tools.forEach((tool, index) => {
      console.log(`   ${index + 1}. ${tool.name}`);
      console.log(`      📝 ${tool.description}`);
      console.log(`      🏷️  Input: ${JSON.stringify(tool.inputSchema.properties, null, 2).substring(0, 100)}...`);
    });

    // Simulate AI assistant queries
    console.log('\n🤖 === SIMULATED AI ASSISTANT QUERIES ===');

    // Query 1: Health check
    console.log('\n1️⃣  AI Query: "Is the security server running?"');
    const pingResult = await client.callTool({
      name: 'ping',
      arguments: {}
    });
    const ping = JSON.parse(pingResult.content[0].text);
    console.log(`   🤖 AI Response: "Security server is ${ping.status} (v${ping.version})"`);

    // Query 2: Vulnerability scan
    console.log('\n2️⃣  AI Query: "Scan nginx:1.27.0 for security vulnerabilities"');
    const scanResult = await client.callTool({
      name: 'scan_image',
      arguments: { image: 'nginx:1.27.0' }
    });
    const scan = JSON.parse(scanResult.content[0].text);
    console.log(`   🤖 AI Response: "Found ${scan.total_vulnerabilities || 0} vulnerabilities in nginx:1.27.0"`);
    console.log(`      🔴 Critical: ${(scan.severity_counts && scan.severity_counts.CRITICAL) || 0}`);
    console.log(`      🟠 High: ${(scan.severity_counts && scan.severity_counts.HIGH) || 0}`);
    console.log(`      🟡 Medium: ${(scan.severity_counts && scan.severity_counts.MEDIUM) || 0}`);

    // Query 3: Security summary
    console.log('\n3️⃣  AI Query: "What\'s the security status of nginx:1.27.0?"');
    const summaryResult = await client.callTool({
      name: 'get_vulnerability_summary',
      arguments: { image: 'nginx:1.27.0' }
    });
    const summary = JSON.parse(summaryResult.content[0].text);
    console.log(`   🤖 AI Response: "nginx:1.27.0 has ${summary.total_vulnerabilities} vulnerabilities affecting ${summary.affected_packages.length} packages"`);

    // Query 4: Remediation options
    console.log('\n4️⃣  AI Query: "How can I fix the vulnerabilities in nginx:1.27.0?"');
    try {
      const remediationResult = await client.callTool({
        name: 'get_image_remediation',
        arguments: { image: 'nginx:1.27.0' }
      });
      const remediation = JSON.parse(remediationResult.content[0].text);
      console.log(`   🤖 AI Response: "I found remediation information for nginx:1.27.0"`);

      if (remediation.patches && remediation.patches.length > 0) {
        console.log(`      � Available patches: ${remediation.patches.length}`);
      } else {
        console.log(`      💡 Remediation analysis available - use trigger_remediation to apply fixes`);
      }
    } catch (error) {
      console.log(`   🤖 AI Response: "I can help you patch nginx:1.27.0 - use trigger_remediation tool"`);
    }

    // Query 5: Trigger automated patching
    console.log('\n5️⃣  AI Query: "Apply security patches to nginx:1.27.0"');
    const patchResult = await client.callTool({
      name: 'trigger_remediation',
      arguments: {
        image: 'nginx:1.27.0',
        output_tag: 'nginx:1.27.0-ai-patched'
      }
    });
    const patch = JSON.parse(patchResult.content[0].text);
    console.log(`   🤖 AI Response: "Started patching process (ID: ${patch.remediation_id})"`);
    console.log(`      🏷️  Patched image will be: ${patch.output_image}`);

    await client.close();

    // Show how this integrates with VS Code
    console.log('\n🎯 === VS CODE INTEGRATION BENEFITS ===');
    console.log('✅ NATURAL LANGUAGE QUERIES:');
    console.log('   • "Check this Dockerfile for security issues"');
    console.log('   • "What vulnerabilities does our app container have?"');
    console.log('   • "How do I fix the security problems in my image?"');
    console.log('   • "Generate a security report for this project"');

    console.log('\n✅ CONTEXTUAL ASSISTANCE:');
    console.log('   • AI understands your workspace and containers');
    console.log('   • Provides specific recommendations for your images');
    console.log('   • Offers automated remediation workflows');
    console.log('   • Integrates with your development workflow');

    console.log('\n✅ AUTOMATED WORKFLOWS:');
    console.log('   • AI can scan images mentioned in conversations');
    console.log('   • Provides real-time security guidance');
    console.log('   • Suggests best practices and fixes');
    console.log('   • Helps maintain security throughout development');

    console.log('\n🔧 === SETUP INSTRUCTIONS ===');
    console.log('1. Start your Copacetic MCP Server:');
    console.log('   docker run -d --name copacetic-mcp-server -p 3000:3000 -v /var/run/docker.sock:/var/run/docker.sock copacetic-mcp-server');

    console.log('\n2. Configure VS Code MCP Settings:');
    console.log('   • Copy .vscode/mcp-settings.json to your VS Code settings');
    console.log('   • Or use .mcp/config.json for global configuration');

    console.log('\n3. Install MCP-compatible VS Code extension:');
    console.log('   • GitHub Copilot (with MCP support)');
    console.log('   • Claude for VS Code (with MCP support)');
    console.log('   • Any extension supporting Model Context Protocol');

    console.log('\n4. Start using natural language queries:');
    console.log('   • Ask about container security in chat');
    console.log('   • Get contextual security recommendations');
    console.log('   • Automate vulnerability management');

    console.log('\n🎉 === MCP INTEGRATION COMPLETE ===');
    console.log('Your AI assistant in VS Code can now use Copacetic security tools!');

  } catch (error) {
    console.error('❌ MCP integration demo failed:', error.message);
    console.log('\n💡 Make sure Copacetic MCP Server is running:');
    console.log('   docker run -d --name copacetic-mcp-server -p 3000:3000 -v /var/run/docker.sock:/var/run/docker.sock copacetic-mcp-server');
  }
}

demonstrateMCPIntegration();
