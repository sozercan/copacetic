#!/usr/bin/env node

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');
const fs = require('fs');

async function patchVulnerableImages() {
  console.log('🔧 Starting automated image patching workflow...\n');

  try {
    // Connect to MCP Server
    const transport = new SSEClientTransport(new URL('http://localhost:3000/sse'));
    const client = new Client({
      name: "vscode-image-patcher",
      version: "1.0.0",
    }, { capabilities: {} });

    await client.connect(transport);

    // Get latest workspace scan
    const workspaceScanFile = getLatestWorkspaceScan();
    if (!workspaceScanFile) {
      console.log('⚠️  No workspace scan results found. Run "Scan Current Workspace Images" first.');
      return;
    }

    const workspaceScan = JSON.parse(fs.readFileSync(workspaceScanFile, 'utf8'));

    // Filter images that need patching (critical or high vulnerabilities)
    const imagesToPatch = workspaceScan.results.filter(result => {
      if (result.error) return false;
      const critical = result.severity?.CRITICAL || 0;
      const high = result.severity?.HIGH || 0;
      return critical > 0 || high > 0;
    });

    if (imagesToPatch.length === 0) {
      console.log('✅ No images require patching (no critical or high severity vulnerabilities)');
      return;
    }

    console.log(`🎯 Found ${imagesToPatch.length} images requiring patches:`);
    imagesToPatch.forEach(img => {
      const critical = img.severity?.CRITICAL || 0;
      const high = img.severity?.HIGH || 0;
      console.log(`   • ${img.image} (${critical} critical, ${high} high)`);
    });
    console.log('');

    const patchResults = [];

    for (const imageResult of imagesToPatch) {
      const { image } = imageResult;
      const outputTag = `${image.replace(':', '-')}-patched:latest`;

      console.log(`🔧 Patching ${image} → ${outputTag}...`);

      try {
        // Trigger remediation
        const remediationResult = await client.callTool({
          name: 'trigger_remediation',
          arguments: {
            image,
            output_tag: outputTag
          }
        });

        const remediation = JSON.parse(remediationResult.content[0].text);

        console.log(`   ✅ Remediation initiated: ${remediation.remediation_id}`);
        console.log(`   📦 Output: ${remediation.output_image}`);

        // Wait a moment then get results
        await new Promise(resolve => setTimeout(resolve, 2000));

        const reportResult = await client.callTool({
          name: 'get_remediation_report',
          arguments: { image }
        });

        const report = JSON.parse(reportResult.content[0].text);

        console.log(`   🎯 Patches applied: ${report.patches_applied}`);
        console.log(`   🛡️  Vulnerabilities fixed: ${report.vulnerabilities_fixed}`);
        console.log(`   ⏱️  Build time: ${report.build_time}`);
        console.log(`   📏 Size change: ${report.size_change}\n`);

        patchResults.push({
          original_image: image,
          patched_image: outputTag,
          remediation_id: remediation.remediation_id,
          patches_applied: report.patches_applied,
          vulnerabilities_fixed: report.vulnerabilities_fixed,
          build_time: report.build_time,
          size_change: report.size_change,
          status: 'success',
          patch_time: new Date().toISOString()
        });

      } catch (error) {
        console.log(`   ❌ Patching failed: ${error.message}\n`);
        patchResults.push({
          original_image: image,
          error: error.message,
          status: 'failed',
          patch_time: new Date().toISOString()
        });
      }
    }

    // Generate patch summary
    generatePatchSummary(patchResults);

    // Update Dockerfiles with patched images (optional)
    await updateDockerfiles(patchResults);

    await client.close();

    // Print summary
    const successful = patchResults.filter(r => r.status === 'success').length;
    const failed = patchResults.filter(r => r.status === 'failed').length;

    console.log('🎯 Automated patching workflow complete!');
    console.log(`✅ Successfully patched: ${successful} images`);
    console.log(`❌ Failed to patch: ${failed} images`);
    console.log(`📊 Results saved to: reports/patch-results-${getDateString()}.json`);

    if (successful > 0) {
      console.log('\n🔄 Next steps:');
      console.log('   1. Review patched images for functionality');
      console.log('   2. Update your Dockerfiles to use patched images');
      console.log('   3. Test applications with patched images');
      console.log('   4. Deploy to production after validation');
    }

  } catch (error) {
    console.error('❌ Patching workflow failed:', error.message);
    process.exit(1);
  }
}

function getLatestWorkspaceScan() {
  if (!fs.existsSync('reports')) return null;

  const files = fs.readdirSync('reports')
    .filter(f => f.startsWith('workspace-scan-') && f.endsWith('.json'))
    .sort()
    .reverse();

  return files.length > 0 ? `reports/${files[0]}` : null;
}

function generatePatchSummary(results) {
  const summary = {
    patch_time: new Date().toISOString(),
    total_images: results.length,
    successful_patches: results.filter(r => r.status === 'success').length,
    failed_patches: results.filter(r => r.status === 'failed').length,
    total_patches_applied: results.reduce((sum, r) => sum + (r.patches_applied || 0), 0),
    total_vulnerabilities_fixed: results.reduce((sum, r) => sum + (r.vulnerabilities_fixed || 0), 0),
    results
  };

  if (!fs.existsSync('reports')) {
    fs.mkdirSync('reports');
  }

  const filename = `patch-results-${getDateString()}.json`;
  fs.writeFileSync(`reports/${filename}`, JSON.stringify(summary, null, 2));
}

async function updateDockerfiles(patchResults) {
  console.log('🔄 Checking for Dockerfile updates...');

  const successfulPatches = patchResults.filter(r => r.status === 'success');

  if (successfulPatches.length === 0) {
    console.log('   ℹ️  No successful patches to apply to Dockerfiles');
    return;
  }

  // Find all Dockerfiles
  const dockerfiles = await findDockerFiles(process.cwd());

  let updatesAvailable = false;

  for (const dockerfile of dockerfiles) {
    const content = fs.readFileSync(dockerfile, 'utf8');
    let updatedContent = content;
    let hasUpdates = false;

    for (const patch of successfulPatches) {
      const originalImage = patch.original_image;
      const patchedImage = patch.patched_image;

      // Check if this Dockerfile uses the original image
      const fromRegex = new RegExp(`FROM\\s+${originalImage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g');

      if (fromRegex.test(content)) {
        console.log(`   📝 Dockerfile ${dockerfile} uses ${originalImage}`);
        console.log(`      Suggested update: FROM ${patchedImage}`);
        updatesAvailable = true;
        hasUpdates = true;
      }
    }

    if (hasUpdates) {
      // Generate suggested Dockerfile (but don't auto-update)
      const suggestedFile = dockerfile + '.patched-suggestion';

      let suggested = updatedContent;
      for (const patch of successfulPatches) {
        const originalImage = patch.original_image;
        const patchedImage = patch.patched_image;
        const fromRegex = new RegExp(`FROM\\s+${originalImage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g');
        suggested = suggested.replace(fromRegex, `FROM ${patchedImage}`);
      }

      fs.writeFileSync(suggestedFile, suggested);
      console.log(`      💡 Suggestion saved to: ${suggestedFile}`);
    }
  }

  if (updatesAvailable) {
    console.log('\n💡 Dockerfile update suggestions generated!');
    console.log('   Review the .patched-suggestion files to update your Dockerfiles');
  } else {
    console.log('   ✅ No Dockerfile updates needed');
  }
}

async function findDockerFiles(dir) {
  const files = [];

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = `${dir}/${entry.name}`;

    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      files.push(...await findDockerFiles(fullPath));
    } else if (entry.isFile() && entry.name.startsWith('Dockerfile')) {
      files.push(fullPath);
    }
  }

  return files;
}

function getDateString() {
  return new Date().toISOString().split('T')[0];
}

patchVulnerableImages();
