import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

export interface RemediationRequest {
  image: string;
  scanReport?: string;
  outputTag: string; // Changed from outputImage to outputTag
  registryCredentials?: string;
  patchStrategy: "auto" | "manual" | "conservative";
}

export interface RemediationResult {
  remediationId: string;
  originalImage: string;
  patchedImage: string;
  patchesApplied: PatchInfo[];
  summary: RemediationSummary;
  buildLogs: string[];
  completedAt: string;
}

export interface PatchInfo {
  packageName: string;
  fromVersion: string;
  toVersion: string;
  vulnerabilitiesFixed: string[];
  patchType: "upgrade" | "backport" | "security-patch";
}

export interface RemediationSummary {
  totalVulnerabilitiesFound: number;
  vulnerabilitiesFixed: number;
  vulnerabilitiesRemaining: number;
  packagesUpgraded: number;
  patchesApplied: number;
  criticalFixed: number;
  highFixed: number;
  mediumFixed: number;
  lowFixed: number;
}

export class ImagePatcher {
  private workDir: string;
  private copaPath: string;

  constructor() {
    this.workDir = path.join(process.cwd(), "patching-workspace");
    this.copaPath = this.findCopaExecutable();
    this.ensureDirectoryExists();
  }

  private findCopaExecutable(): string {
    // Try to find copa executable in common locations
    const possiblePaths = [
      "/usr/local/bin/copa",
      "/usr/bin/copa",
      path.join(process.cwd(), "..", "copa"),
      path.join(process.cwd(), "..", "bin", "copa"),
      "copa", // assume it's in PATH
    ];

    // Check each path to see if the executable exists
    const { execSync } = require('child_process');

    // First try using 'which' to find copa in PATH
    try {
      const whichResult = execSync('which copa', { encoding: 'utf8' }).trim();
      if (whichResult) {
        return whichResult;
      }
    } catch (error) {
      // which failed, continue with manual checking
    }

    // Fall back to checking known paths
    const fs = require('fs');
    for (const possiblePath of possiblePaths) {
      try {
        fs.accessSync(possiblePath, fs.constants.F_OK | fs.constants.X_OK);
        return possiblePath;
      } catch (error) {
        // Path doesn't exist or not executable, continue
      }
    }

    // If nothing found, default to 'copa' and let PATH resolution handle it
    return "copa";
  }

  private async ensureDirectoryExists() {
    try {
      await fs.mkdir(this.workDir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }
  }

  async remediateImage(request: RemediationRequest): Promise<RemediationResult> {
    const remediationId = uuidv4();
    const workspaceDir = path.join(this.workDir, remediationId);

    try {
      await fs.mkdir(workspaceDir, { recursive: true });

      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Starting remediation process`);
      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Created workspace directory: ${workspaceDir}`);

      // Step 1: Pull the original image (if needed)
      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Pulling image ${request.image}`);
      await this.pullImage(request.image);
      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Image pull completed`);

      // Step 2: Use provided scan report or run in comprehensive update mode
      let scanReportPath = request.scanReport;
      let useComprehensiveMode = false;

      if (!scanReportPath) {
        // No scan report provided - use comprehensive update mode
        // Copa will update all packages without requiring Trivy scan
        useComprehensiveMode = true;
        console.log(`[${new Date().toISOString()}] REMEDIATION: Using comprehensive update mode (no scan report provided)`);
      } else {
        console.log(`[${new Date().toISOString()}] REMEDIATION: Using provided scan report: ${scanReportPath}`);
      }

      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Starting Copa patching operation`);
      
      // Step 3: Run copa to patch the image
      const patchResult = await this.runCopa({
        image: request.image,
        scanReport: scanReportPath, // Will be undefined for comprehensive mode
        outputTag: request.outputTag,
        workspaceDir,
        strategy: request.patchStrategy,
        comprehensiveMode: useComprehensiveMode,
      });

      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Copa patching completed successfully`);

      // Step 4: Parse results and generate summary
      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Parsing patch results`);
      const patchesApplied = await this.parsePatchResults(workspaceDir);
      const summary = this.generateRemediationSummary(patchesApplied, useComprehensiveMode);

      // Construct the full output image name for the result
      // outputTag should now be the full tag (e.g., "1.27.0-patched")
      let outputImageName: string;
      const originalColonIndex = request.image.lastIndexOf(':');
      
      if (originalColonIndex !== -1) {
        // Replace the original tag with the new tag
        outputImageName = request.image.substring(0, originalColonIndex + 1) + request.outputTag;
      } else {
        // No tag in original image, append new tag
        outputImageName = `${request.image}:${request.outputTag}`;
      }

      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Generated final output image name: ${outputImageName}`);

      const result: RemediationResult = {
        remediationId,
        originalImage: request.image,
        patchedImage: outputImageName,
        patchesApplied,
        summary,
        buildLogs: patchResult.logs,
        completedAt: new Date().toISOString(),
      };

      // Save result for later retrieval
      await fs.writeFile(
        path.join(workspaceDir, "remediation-result.json"),
        JSON.stringify(result, null, 2)
      );

      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Remediation completed successfully`);

      return result;
    } catch (error) {
      console.log(`[${new Date().toISOString()}] REMEDIATION PROGRESS: Remediation failed with error: ${error instanceof Error ? error.message : String(error)}`);
      throw new Error(`Remediation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async pullImage(image: string): Promise<void> {
    console.log(`[${new Date().toISOString()}] DOCKER PULL: Starting pull for ${image}`);
    await this.executeCommandWithLogs("docker", ["pull", image], (log) => {
      console.log(`[${new Date().toISOString()}] DOCKER PULL: ${log.trim()}`);
    });
    console.log(`[${new Date().toISOString()}] DOCKER PULL: Pull completed for ${image}`);
  }

  private async generateScanReport(image: string, workspaceDir: string): Promise<string> {
    const reportPath = path.join(workspaceDir, "vulnerability-report.json");

    await this.executeCommand("trivy", [
      "image",
      "--format", "json",
      "--output", reportPath,
      image
    ]);

    return reportPath;
  }

  private async runCopa(options: {
    image: string;
    scanReport?: string; // Made optional for comprehensive mode
    outputTag: string;
    workspaceDir: string;
    strategy: string;
    comprehensiveMode?: boolean;
  }): Promise<{ logs: string[] }> {
    const args = [
      "patch",
      "-i", options.image,
      "-t", options.outputTag, // Now just the tag part
      "--loader", "docker",
      "--platform", "linux/arm64", // Target only current platform to avoid emulation issues
    ];

    // Only add scan report if provided (for targeted patching)
    if (options.scanReport) {
      args.push("-r", options.scanReport);
    }

    // Add strategy-specific flags
    if (options.strategy === "conservative") {
      args.push("--ignore-errors");
    }

    const logs: string[] = [];

    // Log the exact Copa command being executed
    console.log(`[${new Date().toISOString()}] COPA COMMAND: ${this.copaPath} ${args.join(' ')}`);
    console.log(`[${new Date().toISOString()}] COPA INPUT IMAGE: ${options.image}`);
    console.log(`[${new Date().toISOString()}] COPA OUTPUT TAG: ${options.outputTag}`);
    console.log(`[${new Date().toISOString()}] COPA PLATFORM: linux/arm64 (single platform to avoid emulation issues)`);
    if (options.comprehensiveMode) {
      console.log(`[${new Date().toISOString()}] COPA MODE: Comprehensive update (all packages)`);
    } else {
      console.log(`[${new Date().toISOString()}] COPA MODE: Targeted patching with scan report`);
    }

    await this.executeCommandWithLogs(this.copaPath, args, (log) => {
      logs.push(log);
      // Stream logs in real-time to console with timestamp
      console.log(`[${new Date().toISOString()}] COPA OUTPUT: ${log.trim()}`);
    });

    return { logs };
  }

  private async parsePatchResults(workspaceDir: string): Promise<PatchInfo[]> {
    // This would parse copa's output to extract patch information
    // For now, return a mock implementation
    const patches: PatchInfo[] = [];

    try {
      // Look for patch logs or result files that copa might generate
      const files = await fs.readdir(workspaceDir);
      for (const file of files) {
        if (file.endsWith(".patch.log")) {
          // Parse patch logs to extract package upgrade information
          const content = await fs.readFile(path.join(workspaceDir, file), "utf-8");
          // Parse content and extract patch info...
        }
      }
    } catch (error) {
      // If we can't parse specific patch info, return empty array
    }

    return patches;
  }

  private generateRemediationSummary(patches: PatchInfo[], comprehensiveMode: boolean = false): RemediationSummary {
    const summary: RemediationSummary = {
      totalVulnerabilitiesFound: 0,
      vulnerabilitiesFixed: 0,
      vulnerabilitiesRemaining: 0,
      packagesUpgraded: patches.length,
      patchesApplied: patches.length,
      criticalFixed: 0,
      highFixed: 0,
      mediumFixed: 0,
      lowFixed: 0,
    };

    // Calculate vulnerabilities fixed from patches
    for (const patch of patches) {
      summary.vulnerabilitiesFixed += patch.vulnerabilitiesFixed.length;
    }

    // In comprehensive mode, we assume we're upgrading all packages for security
    // but don't have specific vulnerability counts
    if (comprehensiveMode && patches.length === 0) {
      // If no specific patch info is available but we ran comprehensive mode,
      // provide a reasonable summary indicating the mode was used
      summary.packagesUpgraded = -1; // Indicates unknown number of packages upgraded
      summary.patchesApplied = -1; // Indicates comprehensive mode was used
    }

    return summary;
  }

  private async executeCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args, { stdio: "pipe" });

      // Set up timeout (10 minutes for regular commands)
      const timeout = setTimeout(() => {
        process.kill('SIGKILL');
        reject(new Error(`Command timed out after 10 minutes: ${command} ${args.join(' ')}`));
      }, 600000); // 10 minutes

      let stderr = "";

      process.stderr?.on("data", (data: any) => {
        stderr += data.toString();
      });

      process.on("close", (code: any) => {
        clearTimeout(timeout);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error: any) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  private async executeCommandWithLogs(
    command: string,
    args: string[],
    onLog: (log: string) => void
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args, { stdio: "pipe" });

      // Set up timeout (15 minutes for Copa operations)
      const timeout = setTimeout(() => {
        process.kill('SIGKILL');
        reject(new Error(`Command timed out after 15 minutes: ${command} ${args.join(' ')}`));
      }, 900000); // 15 minutes

      let stderr = "";

      process.stdout?.on("data", (data: any) => {
        const log = data.toString();
        onLog(log);
      });

      process.stderr?.on("data", (data: any) => {
        const log = data.toString();
        stderr += log;
        onLog(log);
      });

      process.on("close", (code: any) => {
        clearTimeout(timeout);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error: any) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  async getRemediationResult(remediationId: string): Promise<RemediationResult | null> {
    try {
      const workspaceDir = path.join(this.workDir, remediationId);
      const resultFile = path.join(workspaceDir, "remediation-result.json");
      const content = await fs.readFile(resultFile, "utf-8");
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }
}
