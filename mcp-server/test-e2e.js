#!/usr/bin/env node

const https = require('https');
const http = require('http');
const { v4: uuidv4 } = require('uuid');

class MCPTestClient {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.sessionId = null;
  }

  async startSession() {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/sse',
        method: 'GET',
        headers: {
          'Accept': 'text/event-stream',
          'Cache-Control': 'no-cache'
        }
      };

      const req = http.request(options, (res) => {
        if (res.statusCode === 200) {
          // Extract session ID from the response headers or stream
          this.sessionId = res.headers['x-mcp-session-id'];

          console.log(`✅ SSE session established with ID: ${this.sessionId}`);

          // Keep the connection alive
          this.sseConnection = res;

          res.on('data', (chunk) => {
            const data = chunk.toString();
            // Look for session ID in SSE data
            if (data.includes('sessionId') && !this.sessionId) {
              const match = data.match(/"sessionId":"([^"]+)"/);
              if (match) {
                this.sessionId = match[1];
                console.log(`Session ID from SSE data: ${this.sessionId}`);
              }
            }
          });

          res.on('end', () => {
            console.log('SSE connection ended');
          });

          res.on('error', (err) => {
            console.error('SSE connection error:', err);
          });

          // Give the server time to establish the session
          setTimeout(() => {
            if (!this.sessionId) {
              // Try to extract from event stream manually
              this.sessionId = "auto-generated-session";
            }
            resolve();
          }, 1000);
        } else {
          reject(new Error(`Failed to establish SSE connection: ${res.statusCode}`));
        }
      });

      req.on('error', reject);
      req.end();
    });
  }

  async sendMessage(message) {
    return new Promise((resolve, reject) => {
      if (!this.sessionId) {
        reject(new Error('No active session'));
        return;
      }

      const data = JSON.stringify(message);
      const options = {
        hostname: 'localhost',
        port: 3000,
        path: `/message?sessionId=${this.sessionId}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data)
        }
      };

      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(body);
            console.log("Raw response:", JSON.stringify(response, null, 2));
            resolve(response);
          } catch (err) {
            reject(new Error(`Failed to parse response: ${body}`));
          }
        });
      });

      req.on('error', reject);
      req.write(data);
      req.end();
    });
  }

  async listTools() {
    const message = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list"
    };

    return await this.sendMessage(message);
  }

  async callTool(name, args = {}) {
    const message = {
      jsonrpc: "2.0",
      id: Math.floor(Math.random() * 1000),
      method: "tools/call",
      params: {
        name: name,
        arguments: args
      }
    };

    return await this.sendMessage(message);
  }
}

async function runNginxPatchingWorkflow() {
  console.log("🚀 Starting nginx:1.27.0 patching workflow...");

  const client = new MCPTestClient();

  try {
    // Step 0: Establish SSE session
    console.log("\n🔗 Step 0: Establishing SSE session...");
    await client.startSession();
    // Step 1: List available tools
    console.log("\n📋 Step 1: Listing available tools...");
    const toolsResponse = await client.listTools();
    console.log(`Found ${toolsResponse.result.tools.length} tools:`);
    toolsResponse.result.tools.forEach(tool => {
      console.log(`  - ${tool.name}: ${tool.description}`);
    });

    // Step 2: Ping the server
    console.log("\n🏓 Step 2: Pinging server...");
    const pingResponse = await client.callTool("ping");
    console.log("Ping response:", pingResponse.result.content[0].text);

    // Step 3: Scan nginx:1.27.0 image for vulnerabilities
    console.log("\n🔍 Step 3: Scanning nginx:1.27.0 for vulnerabilities...");
    const scanResponse = await client.callTool("scan_image", {
      image: "nginx:1.27.0",
      format: "json"
    });
    console.log("Scan completed:", scanResponse.result.content[0].text);

    // Step 4: Get scan results
    console.log("\n📊 Step 4: Getting scan results...");
    const resultsResponse = await client.callTool("get_scan_results", {
      image: "nginx:1.27.0"
    });
    console.log("Scan results:", resultsResponse.result.content[0].text);

    // Step 5: Generate vulnerability summary
    console.log("\n📈 Step 5: Generating vulnerability summary...");
    const summaryResponse = await client.callTool("get_vulnerability_summary", {
      image: "nginx:1.27.0"
    });
    console.log("Vulnerability summary:", summaryResponse.result.content[0].text);

    // Step 6: Trigger remediation (patching)
    console.log("\n🔧 Step 6: Triggering remediation for nginx:1.27.0...");
    const remediationResponse = await client.callTool("trigger_remediation", {
      image: "nginx:1.27.0",
      output_tag: "nginx:1.27.0-patched"
    });
    console.log("Remediation result:", remediationResponse.result.content[0].text);

    // Step 7: Get remediation report
    console.log("\n📋 Step 7: Getting remediation report...");
    const reportResponse = await client.callTool("get_remediation_report", {
      image: "nginx:1.27.0"
    });
    console.log("Remediation report:", reportResponse.result.content[0].text);

    console.log("\n✅ End-to-end nginx patching workflow completed successfully!");

  } catch (error) {
    console.error("❌ Error in workflow:", error.message);
    process.exit(1);
  }
}

// Run the workflow
runNginxPatchingWorkflow().catch(console.error);
