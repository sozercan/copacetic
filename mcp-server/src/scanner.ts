import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

export interface ScanResult {
  scanId: string;
  image: string;
  vulnerabilities: Vulnerability[];
  summary: VulnerabilitySummary;
  scanTime: string;
  scanner: string;
  format: string;
}

export interface Vulnerability {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  title: string;
  description: string;
  fixedVersion?: string;
  installedVersion: string;
  packageName: string;
  references: string[];
}

export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export class VulnerabilityScanner {
  private scanResultsDir: string;

  constructor() {
    this.scanResultsDir = path.join(process.cwd(), "scan-results");
    this.ensureDirectoryExists();
  }

  private async ensureDirectoryExists() {
    try {
      await fs.mkdir(this.scanResultsDir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }
  }

  async scanImage(
    image: string,
    format: "json" | "sarif" | "cyclonedx" | "spdx" = "json"
  ): Promise<ScanResult> {
    const scanId = uuidv4();
    const outputFile = path.join(this.scanResultsDir, `${scanId}-trivy-${format}.json`);

    try {
      const command = "trivy";
      const args = [
        "image",
        "--format", format,
        "--output", outputFile,
        "--quiet",
        image
      ];

      await this.executeCommand(command, args);

      // Parse the scan results
      const rawResults = await fs.readFile(outputFile, "utf-8");
      const parsedResults = JSON.parse(rawResults);

      const vulnerabilities = this.parseVulnerabilities(parsedResults);
      const summary = this.generateSummary(vulnerabilities);

      const scanResult: ScanResult = {
        scanId,
        image,
        vulnerabilities,
        summary,
        scanTime: new Date().toISOString(),
        scanner: "trivy",
        format,
      };

      // Save processed results
      const processedFile = path.join(this.scanResultsDir, `${scanId}-processed.json`);
      await fs.writeFile(processedFile, JSON.stringify(scanResult, null, 2));

      return scanResult;
    } catch (error) {
      throw new Error(`Scan failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async executeCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args, { stdio: "pipe" });

      let stdout = "";
      let stderr = "";

      process.stdout?.on("data", (data) => {
        stdout += data.toString();
      });

      process.stderr?.on("data", (data) => {
        stderr += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error) => {
        reject(error);
      });
    });
  }

  private parseVulnerabilities(rawResults: any): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    const results = rawResults.Results || [];
    for (const result of results) {
      const vulns = result.Vulnerabilities || [];
      for (const vuln of vulns) {
        vulnerabilities.push({
          id: vuln.VulnerabilityID,
          severity: vuln.Severity || "UNKNOWN",
          title: vuln.Title || vuln.VulnerabilityID,
          description: vuln.Description || "",
          fixedVersion: vuln.FixedVersion,
          installedVersion: vuln.InstalledVersion,
          packageName: vuln.PkgName,
          references: vuln.References || [],
        });
      }
    }

    return vulnerabilities;
  }

  private generateSummary(vulnerabilities: Vulnerability[]): VulnerabilitySummary {
    const summary: VulnerabilitySummary = {
      total: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };

    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
        case "CRITICAL":
          summary.critical++;
          break;
        case "HIGH":
          summary.high++;
          break;
        case "MEDIUM":
          summary.medium++;
          break;
        case "LOW":
          summary.low++;
          break;
        default:
          summary.unknown++;
      }
    }

    return summary;
  }

  async getScanResult(scanId: string): Promise<ScanResult | null> {
    try {
      const processedFile = path.join(this.scanResultsDir, `${scanId}-processed.json`);
      const content = await fs.readFile(processedFile, "utf-8");
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }
}
