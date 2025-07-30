# Copacetic MCP Server Integration Guide

This guide shows how to integrate the Copacetic MCP server with various AI clients and development environments. The server now uses Server-Sent Events (SSE) over HTTP instead of stdio, making it more web-friendly and easier to integrate.

## Quick Start

1. **Build and Start the Server:**
```bash
cd mcp-server
npm install
npm run build
npm run start:http
```

2. **Test the Server:**
```bash
node test-server.js
# or open test-client.html in a browser
```

3. **Check Server Status:**
```bash
curl http://localhost:3000/health
curl http://localhost:3000/info
```

## Integration with AI Clients

### Claude Desktop (HTTP/SSE Mode)

The server now supports HTTP/SSE communication. For Claude Desktop, you would need to use an HTTP transport adapter or configure it to work with the SSE endpoints:

```json
{
  "mcpServers": {
    "copacetic": {
      "command": "node",
      "args": ["/path/to/copacetic/mcp-server/dist/index.js"],
      "env": {
        "NODE_ENV": "production",
        "PORT": "3000"
      }
    }
  }
}
```

### Web-based Clients

For web applications, you can directly connect to the SSE endpoints:

```javascript
// Establish SSE connection
const eventSource = new EventSource('http://localhost:3000/sse');

eventSource.onmessage = (event) => {
  const response = JSON.parse(event.data);
  console.log('Received:', response);
};

// Send messages via POST
async function sendMessage(message) {
  const response = await fetch('http://localhost:3000/message', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-MCP-Session-ID': sessionId
    },
    body: JSON.stringify(message)
  });
}
```

### Continue.dev (HTTP Mode)

Configure Continue.dev to use the HTTP endpoints:

```json
{
  "mcpServers": [
    {
      "name": "copacetic",
      "url": "http://localhost:3000",
      "transport": "sse"
    }
  ]
}
```

### VS Code with MCP Extension

1. Install the MCP extension for VS Code
2. Add server configuration:

```json
{
  "mcp.servers": {
    "copacetic": {
      "command": "node",
      "args": ["/path/to/copacetic/mcp-server/dist/index.js"],
      "cwd": "/path/to/copacetic/mcp-server"
    }
  }
}
```

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Create data directories
mkdir -p data/{scan-results,patching-workspace,reports}

# Create empty credentials file
echo "[]" > data/registry-credentials.json

# Start services
docker-compose up -d
```

### Using Docker Run

```bash
docker build -t copacetic-mcp-server .

docker run -d \
  --name copacetic-mcp-server \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/data:/app/data \
  --stdin --tty \
  copacetic-mcp-server
```

## Usage Examples

### Scanning Container Images

```bash
# Via MCP client, call:
{
  "name": "scan_image",
  "arguments": {
    "image": "nginx:1.21",
    "format": "json"
  }
}
```

### Remediating Vulnerabilities

```bash
# First, create registry integration (if using private registry):
{
  "name": "create_registry_integration",
  "arguments": {
    "registry_url": "your-registry.com",
    "username": "your-username",
    "password": "your-token",
    "name": "My Private Registry"
  }
}

# Then trigger remediation:
{
  "name": "trigger_remediation",
  "arguments": {
    "image": "nginx:1.21",
    "output_image": "nginx:1.21-patched",
    "patch_strategy": "auto"
  }
}

# Check status:
{
  "name": "get_remediation_status",
  "arguments": {
    "remediation_id": "uuid-from-previous-call"
  }
}
```

## Configuration

### Environment Variables

- `NODE_ENV` - Set to "production" for production use
- `LOG_LEVEL` - Set logging level (debug, info, warn, error)
- `COPA_PATH` - Override path to copa binary
- `SCAN_RESULTS_DIR` - Override scan results directory
- `WORKSPACE_DIR` - Override patching workspace directory

### Registry Credentials

Registry credentials are stored in `registry-credentials.json`. For security:

1. Ensure file permissions are restrictive (600)
2. Use tokens instead of passwords when possible
3. Regularly rotate credentials

Example credentials file:
```json
[
  {
    "id": "uuid",
    "name": "Docker Hub",
    "registryUrl": "docker.io",
    "username": "myuser",
    "password": "mytoken",
    "createdAt": "2024-01-01T00:00:00Z"
  }
]
```

## Security Considerations

1. **Container Security:**
   - Run with minimal privileges
   - Use read-only filesystems where possible
   - Regularly update base images

2. **Network Security:**
   - Restrict network access to necessary endpoints
   - Use TLS for registry communications
   - Consider running in isolated networks

3. **Credential Management:**
   - Store credentials securely
   - Use secrets management systems in production
   - Rotate credentials regularly

4. **Image Security:**
   - Validate image signatures when possible
   - Use trusted base images
   - Scan patched images before deployment

## Troubleshooting

### Common Issues

1. **"Command not found" errors:**
   - Ensure Trivy is installed and in PATH
   - Check copa binary location and permissions

2. **Registry authentication failures:**
   - Verify credentials in registry-credentials.json
   - Check network connectivity to registry
   - Ensure token permissions are sufficient

3. **Build failures:**
   - Check Docker socket permissions
   - Verify buildkit connectivity
   - Review build logs for specific errors

### Debug Mode

Enable debug logging:
```bash
NODE_ENV=development LOG_LEVEL=debug npm start
```

### Log Analysis

Check logs for:
- Authentication errors
- Network connectivity issues
- Permission problems
- Resource constraints

## Performance Tuning

1. **Resource Allocation:**
   - Allocate sufficient memory for large images
   - Consider CPU limits for scanning operations
   - Use SSD storage for workspace directories

2. **Caching:**
   - Cache scan results when possible
   - Reuse base image layers
   - Consider registry proxy for frequently accessed images

3. **Parallel Processing:**
   - Limit concurrent operations based on resources
   - Use background processing for long-running tasks
   - Implement queue management for high load

## Monitoring

Monitor these metrics:
- Scan completion times
- Remediation success rates
- Resource utilization
- Error rates by operation type

Example monitoring setup with Prometheus metrics could be added to track:
- `scans_total{status="success|failed"}`
- `remediations_total{status="success|failed"}`
- `scan_duration_seconds`
- `remediation_duration_seconds`

## Support

For issues and support:
1. Check the troubleshooting section above
2. Review server logs for error details
3. Verify configuration and prerequisites
4. Open an issue in the project repository with:
   - Server version
   - Configuration details
   - Error logs
   - Steps to reproduce
