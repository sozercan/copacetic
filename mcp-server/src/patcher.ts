import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

export interface RemediationRequest {
  image: string;
  scanReport?: string;
  outputImage: string;
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
    // Try to find copa executable in the parent copacetic project
    const possiblePaths = [
      path.join(process.cwd(), "..", "copa"),
      path.join(process.cwd(), "..", "bin", "copa"),
      "/usr/local/bin/copa",
      "copa", // assume it's in PATH
    ];

    return possiblePaths[0]; // For now, assume it's available
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

      // Step 1: Pull the original image (if needed)
      await this.pullImage(request.image);

      // Step 2: Generate or use existing scan report
      let scanReportPath = request.scanReport;
      if (!scanReportPath) {
        scanReportPath = await this.generateScanReport(request.image, workspaceDir);
      }

      // Step 3: Run copa to patch the image
      const patchResult = await this.runCopa({
        image: request.image,
        scanReport: scanReportPath,
        outputImage: request.outputImage,
        workspaceDir,
        strategy: request.patchStrategy,
      });

      // Step 4: Parse results and generate summary
      const patchesApplied = await this.parsePatchResults(workspaceDir);
      const summary = this.generateRemediationSummary(patchesApplied);

      const result: RemediationResult = {
        remediationId,
        originalImage: request.image,
        patchedImage: request.outputImage,
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

      return result;
    } catch (error) {
      throw new Error(`Remediation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async pullImage(image: string): Promise<void> {
    return this.executeCommand("docker", ["pull", image]);
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
    scanReport: string;
    outputImage: string;
    workspaceDir: string;
    strategy: string;
  }): Promise<{ logs: string[] }> {
    const args = [
      "patch",
      "-i", options.image,
      "-r", options.scanReport,
      "-t", options.outputImage,
      "--addr", "docker-container://buildkit",
    ];

    // Add strategy-specific flags
    if (options.strategy === "conservative") {
      args.push("--ignore-errors");
    }

    const logs: string[] = [];

    await this.executeCommandWithLogs(this.copaPath, args, (log) => {
      logs.push(log);
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

  private generateRemediationSummary(patches: PatchInfo[]): RemediationSummary {
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

    return summary;
  }

  private async executeCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args, { stdio: "pipe" });

      let stderr = "";

      process.stderr?.on("data", (data: any) => {
        stderr += data.toString();
      });

      process.on("close", (code: any) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error: any) => {
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
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error: any) => {
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
