# SSE-Enabled Copacetic MCP Server

## Overview

The Copacetic MCP Server has been successfully converted from stdio to Server-Sent Events (SSE) communication, making it more web-friendly and suitable for modern AI integrations.

## Architecture Changes

### Before (stdio)
- Communication via stdin/stdout
- Blocking I/O model
- Limited to local/process-based clients
- Single client connection

### After (SSE)
- HTTP-based communication
- Non-blocking event-driven model
- Web-compatible (CORS enabled)
- Multiple concurrent client connections
- RESTful endpoints for health checks and info

## Key Features

### 🌐 **HTTP/SSE Transport**
- **SSE Endpoint**: `GET /sse` - Establishes Server-Sent Events connection
- **Message Endpoint**: `POST /message` - Receives MCP messages
- **Session Management**: Each SSE connection gets a unique session ID
- **CORS Support**: Enabled for web browser clients

### 🔧 **RESTful API**
- **Health Check**: `GET /health` - Server status and metrics
- **Server Info**: `GET /info` - Capabilities and endpoint information
- **Multiple Formats**: JSON responses with proper HTTP status codes

### 🛠️ **Development Tools**
- **Test Client**: Interactive HTML client (`test-client.html`)
- **CLI Client**: Command-line MCP client (`mcp-client.js`)
- **Automated Tests**: HTTP endpoint validation (`test-server.js`)

### 📦 **Container Ready**
- **Docker Support**: Updated Dockerfile with HTTP port exposure
- **Health Checks**: HTTP-based container health monitoring
- **Environment Variables**: Configurable port and host settings

## Usage Examples

### Starting the Server
```bash
# Development mode
npm run dev:http

# Production mode
npm run start:http

# With custom port
PORT=3001 npm run start:http
```

### Testing the Server
```bash
# Automated test
npm run test:server

# Manual health check
curl http://localhost:3000/health

# Server information
curl http://localhost:3000/info
```

### Using the CLI Client
```bash
# Ping test
npm run client ping

# List available tools
npm run client list

# Scan an image
npm run client scan nginx:latest json

# Trigger remediation
npm run client remediate nginx:latest nginx:latest-patched
```

### Web Client
Open `test-client.html` in a web browser for interactive testing.

## Integration Benefits

### For AI Clients
- **Web-Compatible**: Can be integrated into web-based AI applications
- **Scalable**: Supports multiple concurrent connections
- **Reliable**: HTTP-based error handling and status codes
- **Observable**: Built-in health checks and metrics

### For Developers
- **Debuggable**: HTTP requests can be inspected with standard tools
- **Testable**: RESTful endpoints are easy to test
- **Monitorable**: Standard HTTP metrics and logging
- **Deployable**: Works with standard web deployment patterns

## Configuration

### Environment Variables
- `PORT` - Server port (default: 3000)
- `HOST` - Server host (default: 0.0.0.0)
- `NODE_ENV` - Environment mode
- `LOG_LEVEL` - Logging level

### Security Features
- **CORS Configuration**: Configurable origin restrictions
- **DNS Rebinding Protection**: Available but disabled by default for development
- **Session Management**: Unique session IDs for connection tracking
- **Error Handling**: Proper HTTP error responses

## Performance Characteristics

### Concurrency
- Multiple simultaneous SSE connections supported
- Non-blocking message processing
- Background operation tracking with UUIDs

### Resource Usage
- Memory: Stores active transport sessions
- CPU: Event-driven processing, no polling
- Network: Persistent SSE connections with HTTP/1.1

### Scalability
- Horizontal scaling possible with session affinity
- Stateless request handling (except for session mapping)
- Compatible with load balancers and reverse proxies

## Monitoring and Observability

### Health Endpoints
```bash
# Basic health check
curl http://localhost:3000/health
# Returns: status, timestamp, version, activeConnections

# Detailed server info
curl http://localhost:3000/info
# Returns: capabilities, endpoints, activeConnections
```

### Logging
- Server startup and shutdown events
- SSE connection establishment and teardown
- MCP message processing
- Error handling and debugging

### Metrics Available
- Active SSE connections count
- Message processing success/failure rates
- HTTP endpoint response times
- Tool execution statistics

## Migration from stdio

If migrating from the stdio version:

1. **Client Updates**: Clients need to connect via HTTP/SSE instead of stdio
2. **Configuration**: Update any deployment scripts to expose HTTP ports
3. **Monitoring**: Switch to HTTP-based health checks
4. **Testing**: Use provided HTTP test tools instead of stdio tests

## Next Steps

### Potential Enhancements
- **Authentication**: Add API key or JWT-based authentication
- **Rate Limiting**: Implement request rate limiting per session
- **Metrics Collection**: Add Prometheus metrics endpoint
- **WebSocket Support**: Alternative to SSE for bi-directional communication
- **Clustering**: Support for multiple server instances with shared state

### Production Considerations
- **TLS/HTTPS**: Enable HTTPS for production deployments
- **Reverse Proxy**: Deploy behind nginx or similar for production
- **Monitoring**: Integrate with APM tools for observability
- **Backup**: Implement backup strategies for scan results and reports

## Files Changed

### Core Server Files
- `src/index.ts` - Main server converted to HTTP/SSE
- `package.json` - Added SSE dependencies and scripts
- `Dockerfile` - Updated for HTTP port exposure
- `docker-compose.yml` - Added port mappings

### Documentation
- `README.md` - Updated with SSE information
- `INTEGRATION.md` - Added SSE integration examples
- This summary file

### New Files
- `test-client.html` - Interactive web client
- `mcp-client.js` - Command-line MCP client
- `test-server.js` - Updated HTTP-based testing

The SSE-enabled Copacetic MCP Server is now ready for modern AI integrations and web-based deployments while maintaining full compatibility with the Model Context Protocol specification.
