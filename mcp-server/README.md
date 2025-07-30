# Copacetic MCP Server

A Model Context Protocol (MCP) server that provides container vulnerability scanning and remediation capabilities using the Copacetic framework. This server offers similar functionality to commercial vulnerability remediation services like Root.io.

## Features

- **Server-Sent Events (SSE)**: Modern HTTP-based communication instead of stdio
- **RESTful API**: HTTP endpoints for health checks and server information
- **Vulnerability Scanning**: Scan container images using Trivy scanner
- **Image Remediation**: Automatically patch container images with security updates
- **Registry Management**: Manage private registry credentials and integrations
- **Remediation Tracking**: Track remediation history and generate continuity reports
- **Multiple Output Formats**: Support for JSON, SARIF, CycloneDX, and SPDX formats
- **Web-friendly**: Built-in test client and CORS support

## Tools Available

### Core Scanning & Remediation
- `ping` - Health check endpoint
- `scan_image` - Scan container images for vulnerabilities
- `trigger_remediation` - Start asynchronous image patching process
- `get_remediation_status` - Track remediation progress and results

### Registry Management
- `list_registry_credentials` - List configured registry credentials
- `create_registry_integration` - Add new private registry integration

### Reporting & History
- `get_image_remediation` - Get detailed remediation information
- `get_remediation_details_by_scan_id` - Get remediation details by scan ID
- `list_remediation_history` - View remediation history with filtering

## Installation

1. Install dependencies:
```bash
npm install
```

2. Build the project:
```bash
npm run build
```

3. Ensure Copacetic (copa) and Trivy are installed and available in PATH, or modify the paths in the respective modules

## Usage

### Running the Server

Start the MCP server in HTTP/SSE mode:
```bash
npm start
# or with custom port
PORT=3000 npm run start:http
```

The server will be available at `http://localhost:3000` with the following endpoints:
- `GET /health` - Health check
- `GET /info` - Server information and capabilities
- `GET /sse` - SSE connection for MCP communication
- `POST /message` - Message endpoint for MCP requests

### Testing the Server

Run the automated test:
```bash
node test-server.js
```

Or open `test-client.html` in a web browser for interactive testing.

For development with auto-reload:
```bash
npm run dev:http
```

### Example Tool Calls

#### Health Check via HTTP
```bash
curl http://localhost:3000/health
```

#### Server Information
```bash
curl http://localhost:3000/info
```

#### MCP Tool Calls via SSE

The server uses Server-Sent Events for MCP communication. Here are examples using the test client:

#### Scan an Image
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "scan_image",
    "arguments": {
      "image": "nginx:latest",
      "format": "json"
    }
  }
}
```

#### Trigger Remediation
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "trigger_remediation",
    "arguments": {
      "image": "nginx:latest",
      "output_image": "nginx:latest-patched",
      "patch_strategy": "auto"
    }
  }
}
```

#### Check Remediation Status
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "get_remediation_status",
    "arguments": {
      "remediation_id": "uuid-from-trigger-response"
    }
  }
}
```

## Configuration

### Registry Credentials

Registry credentials are stored in `registry-credentials.json`. Use the `create_registry_integration` tool to add new registries:

```json
{
  "name": "create_registry_integration",
  "arguments": {
    "registry_url": "gcr.io",
    "username": "oauth2accesstoken",
    "password": "your-token",
    "name": "Google Container Registry"
  }
}
```

### Copacetic Integration

The server integrates with the Copacetic binary for actual image patching. Ensure copa is:
- Installed and available in PATH, or
- Located at a known path (update `copaPath` in `src/patcher.ts`)

## Development

### Testing
```bash
npm test
```

### Linting
```bash
npm run lint
npm run lint:fix
```

### Building
```bash
npm run build
```

## Architecture

The server is built with TypeScript and uses the Model Context Protocol SDK. It consists of several modules:

- **Scanner** (`src/scanner.ts`) - Vulnerability scanning using external tools
- **Patcher** (`src/patcher.ts`) - Image remediation using Copacetic
- **Registry Manager** (`src/registry.ts`) - Private registry credential management
- **Report Manager** (`src/reports.ts`) - Remediation tracking and reporting
- **Main Server** (`src/index.ts`) - MCP server implementation and tool routing

## Dependencies

- **@modelcontextprotocol/sdk** - MCP protocol implementation
- **zod** - Runtime type checking and validation
- **uuid** - Unique identifier generation
- **External Tools** - Trivy, Grype (for scanning), Copacetic (for patching)

## License

Apache-2.0 License - see LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Run linting and tests
5. Submit a pull request

## Security

This server handles container images and registry credentials. Ensure:
- Credential files are properly secured
- Network access is restricted as needed
- Regular security updates are applied
