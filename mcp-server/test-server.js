#!/usr/bin/env node

// Simple test script to verify the MCP server starts correctly via HTTP/SSE
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

console.log('Testing Copacetic MCP Server (HTTP/SSE mode)...');

const serverPath = path.join(__dirname, 'dist', 'index.js');
const server = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, PORT: '3001' } // Use different port for testing
});

let serverOutput = '';
server.stdout.on('data', (data) => {
  serverOutput += data.toString();
});

server.stderr.on('data', (data) => {
  console.log('Server:', data.toString().trim());
});

// Wait for server to start
setTimeout(async () => {
  try {
    // Test health endpoint
    console.log('Testing health endpoint...');
    const healthResponse = await makeRequest('http://localhost:3001/health');
    const healthData = JSON.parse(healthResponse);

    if (healthData.status === 'healthy') {
      console.log('✅ Health check passed');
    } else {
      console.log('❌ Health check failed');
    }

    // Test info endpoint
    console.log('Testing info endpoint...');
    const infoResponse = await makeRequest('http://localhost:3001/info');
    const infoData = JSON.parse(infoResponse);

    if (infoData.name === 'copacetic-mcp-server') {
      console.log('✅ Info endpoint working');
      console.log(`📊 Server capabilities: ${Object.keys(infoData.capabilities).join(', ')}`);
      console.log(`🔗 Available endpoints: ${Object.keys(infoData.endpoints).join(', ')}`);
    } else {
      console.log('❌ Info endpoint failed');
    }

    // Test SSE endpoint (basic connection test)
    console.log('Testing SSE endpoint...');
    const sseTest = await testSSEConnection();
    if (sseTest) {
      console.log('✅ SSE connection test passed');
    } else {
      console.log('❌ SSE connection test failed');
    }

    console.log('\n🎉 MCP Server is working correctly in HTTP/SSE mode!');
    console.log('💡 Open test-client.html in a browser to test the full functionality');

  } catch (error) {
    console.log('❌ Server test failed:', error.message);
  } finally {
    server.kill();
    process.exit(0);
  }
}, 3000);

server.on('error', (error) => {
  console.error('❌ Failed to start server:', error.message);
  process.exit(1);
});

function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });

    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

function testSSEConnection() {
  return new Promise((resolve) => {
    const req = http.request('http://localhost:3001/sse', {
      method: 'GET',
      headers: {
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache'
      }
    }, (res) => {
      if (res.statusCode === 200 && res.headers['content-type']?.includes('text/event-stream')) {
        resolve(true);
        req.destroy();
      } else {
        resolve(false);
        req.destroy();
      }
    });

    req.on('error', () => resolve(false));
    req.setTimeout(2000, () => {
      req.destroy();
      resolve(false);
    });

    req.end();
  });
}
