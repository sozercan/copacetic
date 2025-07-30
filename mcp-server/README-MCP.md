# Copa MCP Server for GitHub Copilot

This is a Model Context Protocol (MCP) server that integrates container vulnerability scanning and patching capabilities with GitHub Copilot using Copa (Copacetic) and Trivy.

## Features

- **Vulnerability Scanning**: Scan container images for security vulnerabilities using Trivy
- **Image Patching**: Automatically patch container images using Copa (Copacetic)
- **GitHub Copilot Integration**: Use natural language to scan and patch containers

## Prerequisites

1. **Node.js** (v18 or later)
2. **Copa (Copacetic)** - Container patching tool
3. **Trivy** - Vulnerability scanner
4. **Docker** - Container runtime

## Installation

1. Build the MCP server:
```bash
npm install
npm run build
```

2. Test the stdio server:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | npm run start:stdio
```

## GitHub Copilot Configuration

### Method 1: Using the Shell Script (Recommended)

1. Update the `mcp_config.json` file with the absolute path to your installation:
```json
{
  "mcpServers": {
    "copa-mcp": {
      "command": "/absolute/path/to/copa-mcp.sh",
      "args": [],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

2. Configure GitHub Copilot to use this MCP server by adding the configuration to your Copilot settings.

### Method 2: Direct Node.js Command

```json
{
  "mcpServers": {
    "copa-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-server/dist/stdio-server.js"],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

## Usage Examples

Once configured with GitHub Copilot, you can use natural language commands like:

- "Can you scan the nginx:1.26.0 image for vulnerabilities?"
- "Patch the vulnerabilities in the redis:6.2 container image"
- "What security issues are in the ubuntu:20.04 image?"
- "Fix the security vulnerabilities in my container image"

## Available Tools

### `scan_vulnerability`
Scans a container image for security vulnerabilities using Trivy.

**Parameters:**
- `image` (string): Container image name (e.g., 'nginx:1.26.0')

**Example Response:**
```
Vulnerability Scan Results for nginx:1.26.0:
{
  "image": "nginx:1.26.0",
  "total_vulnerabilities": 45,
  "critical": 2,
  "high": 8,
  "medium": 20,
  "low": 15
}

Top 5 Critical/High Vulnerabilities:
- CVE-2023-1234: Buffer overflow in libssl (CRITICAL)
- CVE-2023-5678: Remote code execution (HIGH)
...
```

### `patch_image`
Patches a container image using Copa (Copacetic) to fix vulnerabilities.

**Parameters:**
- `image` (string): Container image name to patch (e.g., 'nginx:1.26.0')

**Example Response:**
```
Image Patching Results for nginx:1.26.0:

✅ Successfully patched image
📦 New patched image: nginx:1.26.0-patched

The patched image has been created with security vulnerabilities fixed.
You can now use the patched image: nginx:1.26.0-patched
```

## Troubleshooting

### Debug Mode

Enable debug logging by setting environment variables:
```bash
DEBUG=1 NODE_ENV=development npm run start:stdio
```

### Common Issues

1. **"Copa not found"**: Ensure Copa is installed and in your PATH
2. **"Trivy not found"**: Ensure Trivy is installed and in your PATH
3. **"Docker not found"**: Ensure Docker is installed and running
4. **Permission denied**: Ensure your user has Docker permissions

### Testing the Server

Test tool listing:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | npm run start:stdio
```

Test vulnerability scanning:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_vulnerability","arguments":{"image":"nginx:alpine"}}}' | npm run start:stdio
```

## Architecture

```
GitHub Copilot
     ↓ (stdio/JSON-RPC)
Copa MCP Server
     ↓
┌─────────┬─────────┬─────────┐
│  Trivy  │  Copa   │ Docker  │
│ Scanner │ Patcher │ Runtime │
└─────────┴─────────┴─────────┘
```

## Development

Run in development mode:
```bash
npm run dev:stdio
```

Watch for changes:
```bash
npm run watch
```

## Contributing

This MCP server is part of the Project Copacetic ecosystem. Contributions are welcome!

## License

Apache 2.0 - See LICENSE file for details.
