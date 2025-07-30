# Trivy-Only Migration Update

## Changes Made

The Copacetic MCP Server has been updated to focus exclusively on Trivy for vulnerability scanning, removing Grype support to simplify the codebase and maintenance.

### Code Changes

1. **Scanner Module (`src/scanner.ts`)**
   - Removed `scannerType` parameter from `scanImage()` method
   - Removed Grype-specific parsing logic
   - Simplified to Trivy-only implementation
   - Updated method signature: `scanImage(image: string, format?: string)`

2. **Main Server (`src/index.ts`)**
   - Updated `ScanImageSchema` to remove `scanner_type` field
   - Modified tool description to specify "Trivy scanner"
   - Simplified scan operation to use Trivy only

3. **Test Client (`test-client.html`)**
   - Removed Grype option from scanner dropdown
   - Added format selection dropdown (JSON, SARIF, CycloneDX, SPDX)
   - Updated button text to "Scan Image (Trivy)"

4. **CLI Client (`mcp-client.js`)**
   - Updated help text to specify Trivy
   - Changed scan command to accept format instead of scanner type
   - Usage: `scan <image> [format]` instead of `scan <image> [scanner]`

5. **Documentation Updates**
   - Updated README.md to remove Grype references
   - Updated INTEGRATION.md examples
   - Updated SSE-MIGRATION.md usage examples

### Benefits of Trivy-Only Approach

✅ **Simplified Maintenance** - Single scanner to maintain and test
✅ **Reduced Dependencies** - No need to install multiple scanners
✅ **Consistent Output** - Single parsing logic and output format
✅ **Better Performance** - Optimized for Trivy's capabilities
✅ **Clear Focus** - Aligns with Trivy's comprehensive vulnerability database

### Trivy Capabilities Retained

- **Multiple Output Formats**: JSON, SARIF, CycloneDX, SPDX
- **Comprehensive Coverage**: OS packages, language dependencies, secrets, misconfigurations
- **Regular Updates**: Frequently updated vulnerability database
- **Fast Scanning**: Efficient container image analysis
- **Detailed Reports**: Rich vulnerability information with fix guidance

### Usage Examples

```bash
# Scan with default JSON format
npm run client scan nginx:latest

# Scan with SARIF format
npm run client scan nginx:latest sarif

# Scan with CycloneDX SBOM format
npm run client scan nginx:latest cyclonedx
```

### API Changes

**Before (with Grype support):**
```json
{
  "name": "scan_image",
  "arguments": {
    "image": "nginx:latest",
    "scanner_type": "trivy",
    "format": "json"
  }
}
```

**After (Trivy-only):**
```json
{
  "name": "scan_image",
  "arguments": {
    "image": "nginx:latest",
    "format": "json"
  }
}
```

The server now provides a streamlined, Trivy-focused vulnerability scanning experience while maintaining all the SSE/HTTP capabilities and MCP tool functionality.
