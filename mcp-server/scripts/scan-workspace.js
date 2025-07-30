#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');
const fs = require('fs');
const path = require('path');

async function scanWorkspaceImages() {
  console.log('🔍 Scanning workspace for container images...\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "vscode-workspace-scanner",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);

    // Find Dockerfiles and docker-compose files
    const dockerfiles = await findDockerFiles(process.cwd());
    const images = extractImagesFromFiles(dockerfiles);

    console.log(`📦 Found ${images.length} container images to scan:`);
    images.forEach(image => console.log(`   • ${image}`));
    console.log('');

    const results = [];

    for (const image of images) {
      console.log(`🔍 Scanning ${image}... (this may take several minutes)`);
      
      let retryCount = 0;
      const maxRetries = 2;
      let scanCompleted = false;

      while (!scanCompleted && retryCount <= maxRetries) {
        try {
          if (retryCount > 0) {
            console.log(`   🔄 Retry attempt ${retryCount}/${maxRetries} for ${image}...`);
          }

          const scanResult = await client.callTool({
            name: 'scan_image',
            arguments: { image }
          });

          const scan = JSON.parse(scanResult.content[0].text);

          // Check if scan is still in progress
          if (scan.status === 'in_progress') {
            console.log(`   ⏳ Scan is taking longer than expected, checking status...`);
            
            // Poll for completion
            let pollAttempts = 0;
            const maxPollAttempts = 30; // 5 minutes of polling
            
            while (pollAttempts < maxPollAttempts) {
              await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
              
              try {
                const statusResult = await client.callTool({
                  name: 'get_scan_status',
                  arguments: { scan_id: scan.scan_id }
                });
                
                const status = JSON.parse(statusResult.content[0].text);
                
                if (status.status === 'completed') {
                  console.log(`   ✅ Scan complete: ${status.total_vulnerabilities} vulnerabilities found`);
                  console.log(`      🔴 Critical: ${status.summary?.critical || 0}`);
                  console.log(`      🟠 High: ${status.summary?.high || 0}`);
                  console.log(`      🟡 Medium: ${status.summary?.medium || 0}`);
                  console.log(`      🟢 Low: ${status.summary?.low || 0}\n`);

                  results.push({
                    image,
                    vulnerabilities: status.total_vulnerabilities,
                    severity: status.summary,
                    scan_time: status.completed_at || new Date().toISOString()
                  });
                  
                  scanCompleted = true;
                  break;
                } else if (status.status === 'failed') {
                  throw new Error(status.error || 'Scan failed');
                }
                
                console.log(`   ⏳ Still scanning... (attempt ${pollAttempts + 1}/${maxPollAttempts})`);
                pollAttempts++;
              } catch (pollError) {
                console.log(`   ⚠️  Status check failed: ${pollError.message}`);
                pollAttempts++;
              }
            }
            
            if (!scanCompleted) {
              throw new Error('Scan timed out after 5 minutes of polling');
            }
          } else {
            // Scan completed immediately
            console.log(`   ✅ Scan complete: ${scan.total_vulnerabilities} vulnerabilities found`);
            console.log(`      🔴 Critical: ${scan.severity_counts?.CRITICAL || 0}`);
            console.log(`      🟠 High: ${scan.severity_counts?.HIGH || 0}`);
            console.log(`      🟡 Medium: ${scan.severity_counts?.MEDIUM || 0}`);
            console.log(`      🟢 Low: ${scan.severity_counts?.LOW || 0}\n`);

            results.push({
              image,
              vulnerabilities: scan.total_vulnerabilities,
              severity: scan.severity_counts,
              scan_time: new Date().toISOString()
            });
            
            scanCompleted = true;
          }

        } catch (error) {
          retryCount++;
          
          if (retryCount > maxRetries) {
            console.log(`   ❌ Failed to scan ${image} after ${maxRetries} retries: ${error.message}\n`);
            results.push({
              image,
              error: error.message,
              scan_time: new Date().toISOString()
            });
            scanCompleted = true; // Exit retry loop
          } else {
            console.log(`   ⚠️  Scan failed, will retry: ${error.message}`);
            await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds before retry
          }
        }
      }
    }

    // Generate VS Code problems
    generateProblemsFile(results);

    // Generate summary report
    generateSummaryReport(results);

    await client.close();

    console.log('🎯 Workspace scan complete!');
    console.log(`📊 Results saved to: reports/workspace-scan-${new Date().toISOString().split('T')[0]}.json`);

  } catch (error) {
    console.error('❌ Workspace scan failed:', error.message);
    process.exit(1);
  }
}

async function findDockerFiles(dir) {
  const files = [];

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      files.push(...await findDockerFiles(fullPath));
    } else if (entry.isFile()) {
      if (entry.name.startsWith('Dockerfile') ||
          entry.name === 'docker-compose.yml' ||
          entry.name === 'docker-compose.yaml') {
        files.push(fullPath);
      }
    }
  }

  return files;
}

function extractImagesFromFiles(files) {
  const images = new Set();

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');

    if (file.includes('Dockerfile')) {
      // Extract FROM statements
      const fromMatches = content.match(/^FROM\s+([^\s]+)/gm);
      if (fromMatches) {
        fromMatches.forEach(match => {
          const image = match.replace(/^FROM\s+/, '').split(' ')[0];
          if (!image.startsWith('$') && image !== 'scratch') {
            images.add(image);
          }
        });
      }
    } else if (file.includes('docker-compose')) {
      // Extract image definitions
      const imageMatches = content.match(/image:\s*([^\s]+)/g);
      if (imageMatches) {
        imageMatches.forEach(match => {
          const image = match.replace(/image:\s*/, '');
          if (!image.startsWith('$')) {
            images.add(image);
          }
        });
      }
    }
  }

  return Array.from(images);
}

function generateProblemsFile(results) {
  const problems = [];

  results.forEach(result => {
    if (result.vulnerabilities > 0) {
      const critical = result.severity?.CRITICAL || 0;
      const high = result.severity?.HIGH || 0;

      if (critical > 0) {
        problems.push({
          severity: 'error',
          message: `${critical} critical vulnerabilities found in ${result.image}`,
          source: 'copacetic'
        });
      }

      if (high > 0) {
        problems.push({
          severity: 'warning',
          message: `${high} high severity vulnerabilities found in ${result.image}`,
          source: 'copacetic'
        });
      }
    }
  });

  if (!fs.existsSync('reports')) {
    fs.mkdirSync('reports');
  }

  fs.writeFileSync('reports/problems.json', JSON.stringify(problems, null, 2));
}

function generateSummaryReport(results) {
  const summary = {
    scan_time: new Date().toISOString(),
    total_images: results.length,
    successful_scans: results.filter(r => !r.error).length,
    failed_scans: results.filter(r => r.error).length,
    total_vulnerabilities: results.reduce((sum, r) => sum + (r.vulnerabilities || 0), 0),
    severity_summary: {
      CRITICAL: results.reduce((sum, r) => sum + (r.severity?.CRITICAL || 0), 0),
      HIGH: results.reduce((sum, r) => sum + (r.severity?.HIGH || 0), 0),
      MEDIUM: results.reduce((sum, r) => sum + (r.severity?.MEDIUM || 0), 0),
      LOW: results.reduce((sum, r) => sum + (r.severity?.LOW || 0), 0)
    },
    results
  };

  if (!fs.existsSync('reports')) {
    fs.mkdirSync('reports');
  }

  const filename = `workspace-scan-${new Date().toISOString().split('T')[0]}.json`;
  fs.writeFileSync(`reports/${filename}`, JSON.stringify(summary, null, 2));
}

scanWorkspaceImages();
