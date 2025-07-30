# VS Code Integration Guide for Copacetic MCP Server

## Overview
This guide shows how to integrate the containerized Copacetic MCP server with VS Code for seamless vulnerability management directly in your development environment.

## Integration Methods

### 1. 🎯 MCP Extension Integration (Recommended)

VS Code can connect to MCP servers through extensions that support the Model Context Protocol.

#### Prerequisites
- VS Code with MCP-compatible extension
- Running containerized MCP server
- Docker Desktop or compatible container runtime

#### Configuration
Add to your VS Code settings.json:
```json
{
  "mcp.servers": {
    "copacetic": {
      "command": "curl",
      "args": ["-X", "POST", "http://localhost:3000/message"],
      "transport": "sse",
      "endpoint": "http://localhost:3000/sse"
    }
  }
}
```

### 2. 🔌 VS Code Extension Development

Create a dedicated VS Code extension for Copacetic integration.

#### Extension Manifest (package.json)
```json
{
  "name": "copacetic-security",
  "displayName": "Copacetic Security Scanner",
  "version": "1.0.0",
  "engines": { "vscode": "^1.74.0" },
  "categories": ["Other"],
  "activationEvents": ["onStartupFinished"],
  "contributes": {
    "commands": [
      {
        "command": "copacetic.scanImage",
        "title": "Scan Container Image",
        "category": "Copacetic"
      },
      {
        "command": "copacetic.patchImage",
        "title": "Patch Container Image",
        "category": "Copacetic"
      }
    ],
    "views": {
      "explorer": [
        {
          "id": "copaceticVulnerabilities",
          "name": "Security Vulnerabilities",
          "when": "copacetic.enabled"
        }
      ]
    }
  }
}
```

### 3. 🚀 Task Integration

Integrate with VS Code tasks for automated workflows.

#### Tasks Configuration (.vscode/tasks.json)
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Start Copacetic MCP Server",
      "type": "shell",
      "command": "docker",
      "args": [
        "run", "-d", "--name", "copacetic-mcp-server",
        "-p", "3000:3000",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "copacetic-mcp-server"
      ],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always"
      }
    },
    {
      "label": "Scan Current Dockerfile",
      "type": "shell",
      "command": "node",
      "args": ["${workspaceFolder}/mcp-server/scan-dockerfile.js"],
      "group": "test",
      "dependsOn": "Start Copacetic MCP Server"
    },
    {
      "label": "Generate Security Report",
      "type": "shell",
      "command": "node",
      "args": ["${workspaceFolder}/mcp-server/generate-report.js"],
      "group": "test"
    }
  ]
}
```

### 4. 📋 Workspace Integration

#### Launch Configuration (.vscode/launch.json)
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug MCP Server",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}/mcp-server/src/index.ts",
      "env": {
        "NODE_ENV": "development",
        "MCP_PORT": "3000"
      },
      "console": "integratedTerminal"
    }
  ]
}
```

#### Settings (.vscode/settings.json)
```json
{
  "copacetic.autoScan": true,
  "copacetic.serverUrl": "http://localhost:3000",
  "copacetic.enableNotifications": true,
  "files.associations": {
    "Dockerfile*": "dockerfile",
    "*.copa": "yaml"
  }
}
```

## Implementation Examples

### A. Quick Scan Command
Create a command palette integration for instant vulnerability scanning.

### B. Status Bar Integration
Show real-time security status in the VS Code status bar.

### C. Problems Panel Integration
Display vulnerabilities as problems with quick fixes.

### D. IntelliSense Integration
Provide security suggestions and auto-completion.

## Automation Workflows

### Pre-commit Hooks
Automatically scan images before commits:
```bash
#!/bin/sh
# .git/hooks/pre-commit
node mcp-server/scan-commit-images.js
```

### CI/CD Integration
Include in your GitHub Actions or other CI systems:
```yaml
- name: Security Scan
  run: |
    docker run copacetic-mcp-server
    node mcp-server/ci-scan.js
```

## Benefits

✅ **Seamless Integration**: Work within familiar VS Code environment
✅ **Real-time Feedback**: Instant vulnerability detection
✅ **Automated Workflows**: Background scanning and patching
✅ **Team Collaboration**: Share security configurations
✅ **CI/CD Ready**: Integrate with existing pipelines
