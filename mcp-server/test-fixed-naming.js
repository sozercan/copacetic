#!/usr/bin/env node

// Test the fixed image naming with explicit output tag

async function testFixedNaming() {
  console.log('Testing fixed image naming...');

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

    // Test remediation call with explicit output tag
    console.log('Testing remediation with explicit output_tag...');
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
          name: 'trigger_remediation',
          arguments: {
            image: 'nginx:1.20',
            output_tag: 'nginx-fixed:1.20'  // Explicit tag to avoid duplication
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

    console.log('Remediation request submitted. Check logs for progress...');

  } catch (error) {
    console.error('Test failed:', error);
  }
}

testFixedNaming();
