#!/usr/bin/env node

// Test script to simulate GitHub Copilot MCP interaction
const http = require('http');

async function testMCPConnection() {
  console.log('Testing MCP server connection...');

  // First, test health endpoint
  try {
    const healthResponse = await fetch('http://localhost:3000/health');
    const healthData = await healthResponse.json();
    console.log('Health check:', healthData);
  } catch (error) {
    console.error('Health check failed:', error);
    return;
  }

  // Test establishing SSE connection
  try {
    console.log('Establishing SSE connection...');
    const sseResponse = await fetch('http://localhost:3000/sse');

    console.log('SSE Response headers:', Object.fromEntries(sseResponse.headers.entries()));
    const sessionId = sseResponse.headers.get('X-MCP-Session-ID');
    console.log('Session ID:', sessionId);

    if (!sessionId) {
      console.error('No session ID received');
      return;
    }

    // Test tool call
    console.log('Testing tool call...');
    const toolCallResponse = await fetch('http://localhost:3000/message', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-MCP-Session-ID': sessionId
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'scan_image',
          arguments: {
            image: 'nginx:1.26.0'
          }
        }
      })
    });

    const toolCallData = await toolCallResponse.json();
    console.log('Tool call response:', toolCallData);

  } catch (error) {
    console.error('SSE/Tool call failed:', error);
  }
}

testMCPConnection();
