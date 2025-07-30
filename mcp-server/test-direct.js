#!/usr/bin/env node

// Simple test using direct tools instead of MCP protocol
const scanner = require('./dist/scanner');
const patcher = require('./dist/patcher');

async function runDirectTest() {
  console.log("🚀 Direct nginx:1.27.0 patching workflow...");

  try {
    // Step 1: Scan nginx:1.27.0 image for vulnerabilities
    console.log("\n🔍 Step 1: Scanning nginx:1.27.0 for vulnerabilities...");
    const scanResult = await scanner.scanImage("nginx:1.27.0", "json");
    console.log("Scan completed:", scanResult.summary || "Scan initiated");

    // Step 2: Check if we have results
    console.log("\n📊 Step 2: Checking scan results...");
    const resultsFile = `/tmp/copacetic-mcp/scan-results/nginx_1.27.0_trivy.json`;
    const fs = require('fs');

    if (fs.existsSync(resultsFile)) {
      const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
      console.log(`Found ${results.Results?.length || 0} vulnerability categories`);

      // Count total vulnerabilities
      let totalVulns = 0;
      if (results.Results) {
        results.Results.forEach(result => {
          if (result.Vulnerabilities) {
            totalVulns += result.Vulnerabilities.length;
          }
        });
      }
      console.log(`Total vulnerabilities found: ${totalVulns}`);
    } else {
      console.log("Scan results not found yet, scan may be in progress...");
    }

    // Step 3: Trigger remediation
    console.log("\n🔧 Step 3: Triggering remediation for nginx:1.27.0...");
    const patchResult = await patcher.remediateImage("nginx:1.27.0", {
      outputTag: "nginx:1.27.0-patched",
      buildTimeout: 300
    });
    console.log("Remediation result:", patchResult);

    console.log("\n✅ Direct nginx patching workflow completed!");

  } catch (error) {
    console.error("❌ Error in workflow:", error.message);
    if (error.stack) {
      console.error(error.stack);
    }
  }
}

// Run the workflow
runDirectTest().catch(console.error);
