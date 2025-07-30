#!/bin/bash

# Copa MCP Server Launcher
# This script launches the Copa MCP server for GitHub Copilot integration

cd "$(dirname "$0")"

# Ensure we have all required tools available
if ! command -v copa &> /dev/null; then
    echo "Error: Copa (Copacetic) not found in PATH" >&2
    echo "Please ensure Copa is installed and available" >&2
    exit 1
fi

if ! command -v trivy &> /dev/null; then
    echo "Error: Trivy not found in PATH" >&2
    echo "Please ensure Trivy is installed and available" >&2
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "Error: Docker not found in PATH" >&2
    echo "Please ensure Docker is installed and available" >&2
    exit 1
fi

# Log startup info to stderr (so it doesn't interfere with MCP communication)
echo "[$(date)] Starting Copa MCP Server..." >&2
echo "[$(date)] Copa version: $(copa --help | head -1)" >&2
echo "[$(date)] Trivy version: $(trivy --version)" >&2
echo "[$(date)] Docker version: $(docker --version)" >&2

# Launch the MCP server
exec node dist/stdio-server.js
