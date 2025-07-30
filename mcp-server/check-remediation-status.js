#!/usr/bin/env node

// Check remediation status after running test

async function checkStatus() {
  console.log('Checking remediation status...');

  try {
    // Test establishing SSE connection
    console.log('Establishing SSE connection...');
    const sseResponse = await fetch('http://localhost:3000/sse');

    const sessionId = sseResponse.headers.get('X-MCP-Session-ID');
    console.log('Session ID:', sessionId);

    if (!sessionId) {
      console.error('No session ID received');
      return;
    }

    // Check status
    console.log('Checking scan status...');

    const statusResponse = await fetch('http://localhost:3000/message', {
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
          name: 'get_scan_status',
          arguments: {}
        }
      })
    });

    if (!statusResponse.ok) {
      console.error('Status call failed:', statusResponse.status, statusResponse.statusText);
      return;
    }

    const responseText = await statusResponse.text();
    console.log('Raw status response:', responseText);

    try {
      const statusData = JSON.parse(responseText);
      console.log('Parsed status response:', JSON.stringify(statusData, null, 2));
    } catch (parseError) {
      console.log('Could not parse as JSON, raw response:', responseText);
    }

  } catch (error) {
    console.error('Status check failed:', error);
  }
}

checkStatus();
