import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

// Enhanced logging utility
class Logger {
  private static formatTimestamp(): string {
    return new Date().toISOString();
  }

  static info(operation: string, message: string, data?: any) {
    console.error(`[${this.formatTimestamp()}] INFO [${operation}] ${message}`, data ? JSON.stringify(data, null, 2) : '');
  }

  static error(operation: string, message: string, error?: any) {
    console.error(`[${this.formatTimestamp()}] ERROR [${operation}] ${message}`, error ? (error.stack || error.message || error) : '');
  }

  static debug(operation: string, message: string, data?: any) {
    console.error(`[${this.formatTimestamp()}] DEBUG [${operation}] ${message}`, data ? JSON.stringify(data, null, 2) : '');
  }
}

const server = new Server(
  {
    name: "copa-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

Logger.info('SERVER', 'Initializing Copa MCP Server for GitHub Copilot');

// Tool schemas
const ScanImageSchema = z.object({
  image: z.string().describe("Container image name (e.g., 'nginx:latest')"),
});

// Register tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  Logger.debug('TOOLS', 'Listing available tools');
  return {
    tools: [
      {
        name: "scan_vulnerability",
        description: "Scan a container image for security vulnerabilities using Trivy",
        inputSchema: {
          type: "object",
          properties: {
            image: {
              type: "string",
              description: "Container image to scan (e.g., 'nginx:1.26.0')",
            },
          },
          required: ["image"],
        },
      },
      {
        name: "patch_image",
        description: "Patch a container image using Copa (Copacetic) to fix vulnerabilities",
        inputSchema: {
          type: "object",
          properties: {
            image: {
              type: "string",
              description: "Container image to patch (e.g., 'nginx:1.26.0')",
            },
          },
          required: ["image"],
        },
      },
    ],
  };
});

// Tool call handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  Logger.info('MCP', `Tool call received: ${name}`, { arguments: args });

  try {
    switch (name) {
      case "scan_vulnerability": {
        const { image } = ScanImageSchema.parse(args);

        Logger.info('SCAN', `Starting vulnerability scan for ${image}`);

        // Execute Trivy scan
        const { spawn } = await import('child_process');

        return new Promise((resolve, reject) => {
          const scanProcess = spawn('trivy', [
            'image',
            '--format', 'json',
            '--quiet',
            image
          ]);

          let scanOutput = '';
          let scanError = '';

          scanProcess.stdout.on('data', (data) => {
            scanOutput += data.toString();
          });

          scanProcess.stderr.on('data', (data) => {
            scanError += data.toString();
          });

          scanProcess.on('close', (code) => {
            if (code !== 0) {
              Logger.error('SCAN', `Trivy scan failed with code ${code}`, { error: scanError });
              reject(new Error(`Scan failed: ${scanError}`));
              return;
            }

            try {
              const scanResult = JSON.parse(scanOutput);
              const vulnerabilities = scanResult.Results?.[0]?.Vulnerabilities || [];

              Logger.info('SCAN', `Scan completed for ${image}`, {
                vulnerabilityCount: vulnerabilities.length
              });

              const summary = {
                image,
                total_vulnerabilities: vulnerabilities.length,
                critical: vulnerabilities.filter((v: any) => v.Severity === 'CRITICAL').length,
                high: vulnerabilities.filter((v: any) => v.Severity === 'HIGH').length,
                medium: vulnerabilities.filter((v: any) => v.Severity === 'MEDIUM').length,
                low: vulnerabilities.filter((v: any) => v.Severity === 'LOW').length,
              };

              resolve({
                content: [
                  {
                    type: "text",
                    text: `Vulnerability Scan Results for ${image}:
${JSON.stringify(summary, null, 2)}

Top 5 Critical/High Vulnerabilities:
${vulnerabilities
  .filter((v: any) => v.Severity === 'CRITICAL' || v.Severity === 'HIGH')
  .slice(0, 5)
  .map((v: any) => `- ${v.VulnerabilityID}: ${v.Title} (${v.Severity})`)
  .join('\n')}

Total vulnerabilities found: ${vulnerabilities.length}
Recommendation: Run patch_image to remediate these vulnerabilities.`,
                  },
                ],
              });
            } catch (error: any) {
              Logger.error('SCAN', 'Failed to parse scan results', error);
              reject(new Error(`Failed to parse scan results: ${error?.message || error}`));
            }
          });
        });
      }

      case "patch_image": {
        const { image } = ScanImageSchema.parse(args);

        Logger.info('PATCH', `Starting image patching for ${image}`);

        // Execute Copa patch
        const { spawn } = await import('child_process');

        return new Promise((resolve, reject) => {
          const patchProcess = spawn('copa', [
            'patch',
            '--image', image,
            '--tag', `${image}-patched`,
            '--format', 'json'
          ]);

          let patchOutput = '';
          let patchError = '';

          patchProcess.stdout.on('data', (data) => {
            patchOutput += data.toString();
          });

          patchProcess.stderr.on('data', (data) => {
            patchError += data.toString();
          });

          patchProcess.on('close', (code) => {
            if (code !== 0) {
              Logger.error('PATCH', `Copa patch failed with code ${code}`, { error: patchError });
              reject(new Error(`Patch failed: ${patchError}`));
              return;
            }

            Logger.info('PATCH', `Patch completed for ${image}`);

            resolve({
              content: [
                {
                  type: "text",
                  text: `Image Patching Results for ${image}:

✅ Successfully patched image
📦 New patched image: ${image}-patched

The patched image has been created with security vulnerabilities fixed.
You can now use the patched image: ${image}-patched

Output: ${patchOutput}`,
                },
              ],
            });
          });
        });
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    Logger.error('MCP', `Tool call failed: ${name}`, error);
    throw error;
  }
});

async function main() {
  Logger.info('STARTUP', 'Starting Copa MCP server for GitHub Copilot via stdio');

  const transport = new StdioServerTransport();
  await server.connect(transport);

  Logger.info('STARTUP', 'Copa MCP server connected and ready');
}

if (require.main === module) {
  main().catch((error) => {
    Logger.error('STARTUP', 'Server startup failed', error);
    process.exit(1);
  });
}
