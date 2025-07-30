#!/usr/bin/env node

/**
 * Simple MCP client for testing the Copacetic MCP Server
 * Usage: node mcp-client.js [command] [args...]
 * Examples:
 *   node mcp-client.js ping
 *   node mcp-client.js scan nginx:latest
 *   node mcp-client.js remediate nginx:latest nginx:latest-patched
 */

const EventSource = require('eventsource');
const fetch = require('node-fetch');

class MCPClient {
  constructor(serverUrl = 'http://localhost:3000') {
    this.serverUrl = serverUrl;
    this.eventSource = null;
    this.sessionId = null;
    this.messageId = 1;
    this.pendingRequests = new Map();
  }

  async connect() {
    return new Promise((resolve, reject) => {
      console.log(`Connecting to MCP server at ${this.serverUrl}...`);

      this.eventSource = new EventSource(`${this.serverUrl}/sse`);

      this.eventSource.onopen = () => {
        console.log('✅ Connected to MCP server');
        this.sessionId = 'client-' + Math.random().toString(36).substr(2, 9);
        resolve();
      };

      this.eventSource.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleMessage(message);
        } catch (error) {
          console.error('Error parsing message:', error);
        }
      };

      this.eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        reject(error);
      };
    });
  }

  handleMessage(message) {
    if (message.id && this.pendingRequests.has(message.id)) {
      const { resolve } = this.pendingRequests.get(message.id);
      this.pendingRequests.delete(message.id);
      resolve(message);
    } else {
      console.log('Received message:', JSON.stringify(message, null, 2));
    }
  }

  async sendMessage(message) {
    if (!this.sessionId) {
      throw new Error('Not connected to server');
    }

    const response = await fetch(`${this.serverUrl}/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-MCP-Session-ID': this.sessionId
      },
      body: JSON.stringify(message)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
  }

  async callTool(name, args = {}) {
    const id = this.messageId++;
    const message = {
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: {
        name,
        arguments: args
      }
    };

    return new Promise(async (resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });

      try {
        await this.sendMessage(message);

        // Set timeout for response
        setTimeout(() => {
          if (this.pendingRequests.has(id)) {
            this.pendingRequests.delete(id);
            reject(new Error('Request timeout'));
          }
        }, 30000); // 30 second timeout
      } catch (error) {
        this.pendingRequests.delete(id);
        reject(error);
      }
    });
  }

  async listTools() {
    const id = this.messageId++;
    const message = {
      jsonrpc: "2.0",
      id,
      method: "tools/list",
      params: {}
    };

    return new Promise(async (resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });

      try {
        await this.sendMessage(message);
      } catch (error) {
        this.pendingRequests.delete(id);
        reject(error);
      }
    });
  }

  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.sessionId = null;
    console.log('Disconnected from MCP server');
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command) {
    console.log('Usage: node mcp-client.js [command] [args...]');
    console.log('Commands:');
    console.log('  ping                           - Test server connectivity');
    console.log('  list                          - List available tools');
    console.log('  scan <image> [format]         - Scan image for vulnerabilities with Trivy');
    console.log('  remediate <image> <output>    - Remediate image vulnerabilities');
    console.log('  status <remediation-id>       - Check remediation status');
    console.log('  credentials                   - List registry credentials');
    return;
  }

  const client = new MCPClient();

  try {
    await client.connect();

    switch (command) {
      case 'ping':
        console.log('Pinging server...');
        const pingResponse = await client.callTool('ping');
        console.log('Ping response:', JSON.stringify(pingResponse.result, null, 2));
        break;

      case 'list':
        console.log('Listing available tools...');
        const toolsResponse = await client.listTools();
        if (toolsResponse.result && toolsResponse.result.tools) {
          console.log(`Found ${toolsResponse.result.tools.length} tools:`);
          toolsResponse.result.tools.forEach(tool => {
            console.log(`  - ${tool.name}: ${tool.description}`);
          });
        }
        break;

      case 'scan':
        const image = args[1];
        const format = args[2] || 'json';
        if (!image) {
          console.error('Error: Image name required');
          return;
        }
        console.log(`Scanning image ${image} with Trivy (format: ${format})...`);
        const scanResponse = await client.callTool('scan_image', {
          image,
          format
        });
        console.log('Scan response:', JSON.stringify(scanResponse.result, null, 2));
        break;

      case 'remediate':
        const inputImage = args[1];
        const outputImage = args[2];
        if (!inputImage || !outputImage) {
          console.error('Error: Input and output image names required');
          return;
        }
        console.log(`Remediating ${inputImage} -> ${outputImage}...`);
        const remediateResponse = await client.callTool('trigger_remediation', {
          image: inputImage,
          output_image: outputImage,
          patch_strategy: 'auto'
        });
        console.log('Remediation response:', JSON.stringify(remediateResponse.result, null, 2));
        break;

      case 'status':
        const remediationId = args[1];
        if (!remediationId) {
          console.error('Error: Remediation ID required');
          return;
        }
        console.log(`Checking status of remediation ${remediationId}...`);
        const statusResponse = await client.callTool('get_remediation_status', {
          remediation_id: remediationId
        });
        console.log('Status response:', JSON.stringify(statusResponse.result, null, 2));
        break;

      case 'credentials':
        console.log('Listing registry credentials...');
        const credsResponse = await client.callTool('list_registry_credentials');
        console.log('Credentials response:', JSON.stringify(credsResponse.result, null, 2));
        break;

      default:
        console.error(`Unknown command: ${command}`);
        return;
    }

  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    client.disconnect();
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
