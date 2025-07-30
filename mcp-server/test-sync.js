#!/usr/bin/env node

// Test script to verify the fixed MCP server
async function testMCPSync() {
  console.log('Testing synchronized MCP server...');

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

    // Test tool call with await for completion
    console.log('Testing synchronous scan tool call...');
    const startTime = Date.now();

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
            image: 'alpine:latest',
            format: 'json'
          }
        }
      })
    });

    const endTime = Date.now();
    console.log(`Tool call took ${endTime - startTime}ms`);

    if (!toolCallResponse.ok) {
      console.error('Tool call failed:', toolCallResponse.status, toolCallResponse.statusText);
      const errorText = await toolCallResponse.text();
      console.error('Error:', errorText);
      return;
    }

    const responseText = await toolCallResponse.text();
    console.log('Raw response:', responseText);

    try {
      const toolCallData = JSON.parse(responseText);
      console.log('Parsed tool call response:', JSON.stringify(toolCallData, null, 2));
    } catch (parseError) {
      console.log('Could not parse as JSON, raw response:', responseText);
    }

  } catch (error) {
    console.error('Test failed:', error);
  }
}

testMCPSync();
