import { promises as fs } from "fs";
import path from "path";
import { RemediationResult } from "./patcher";
import { ScanResult } from "./scanner";

export interface RemediationHistory {
  remediationId: string;
  image: string;
  timestamp: string;
  status: "completed" | "failed" | "in_progress";
  vulnerabilitiesFixed: number;
  packagesUpgraded: number;
  patchedImage?: string;
}

export interface RemediationContinuitySummary {
  fqin: string; // Fully Qualified Image Name
  totalRemediations: number;
  rootPatches: number;
  upstreamUpgrades: number;
  firstRemediation: string;
  lastRemediation: string;
  vulnerabilityTrends: {
    critical: { before: number; after: number };
    high: { before: number; after: number };
    medium: { before: number; after: number };
    low: { before: number; after: number };
  };
}

export class ReportManager {
  private reportsDir: string;
  private historyFile: string;

  constructor() {
    this.reportsDir = path.join(process.cwd(), "reports");
    this.historyFile = path.join(this.reportsDir, "remediation-history.json");
    this.ensureDirectoryExists();
  }

  private async ensureDirectoryExists() {
    try {
      await fs.mkdir(this.reportsDir, { recursive: true });

      // Ensure history file exists
      try {
        await fs.access(this.historyFile);
      } catch (error) {
        await fs.writeFile(this.historyFile, JSON.stringify([], null, 2));
      }
    } catch (error) {
      // Directory might already exist
    }
  }

  async recordRemediation(result: RemediationResult): Promise<void> {
    const historyEntry: RemediationHistory = {
      remediationId: result.remediationId,
      image: result.originalImage,
      timestamp: result.completedAt,
      status: "completed",
      vulnerabilitiesFixed: result.summary.vulnerabilitiesFixed,
      packagesUpgraded: result.summary.packagesUpgraded,
      patchedImage: result.patchedImage,
    };

    try {
      const content = await fs.readFile(this.historyFile, "utf-8");
      const history: RemediationHistory[] = JSON.parse(content);
      history.push(historyEntry);

      // Keep only the last 1000 entries
      if (history.length > 1000) {
        history.splice(0, history.length - 1000);
      }

      await fs.writeFile(this.historyFile, JSON.stringify(history, null, 2));
    } catch (error) {
      throw new Error(`Failed to record remediation: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getRemediationHistory(image?: string, limit: number = 50): Promise<RemediationHistory[]> {
    try {
      const content = await fs.readFile(this.historyFile, "utf-8");
      const history: RemediationHistory[] = JSON.parse(content);

      let filteredHistory = history;
      if (image) {
        filteredHistory = history.filter(entry => entry.image === image);
      }

      // Sort by timestamp (newest first) and limit results
      return filteredHistory
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);
    } catch (error) {
      return [];
    }
  }

  async getRemediationDetails(remediationId: string): Promise<RemediationResult | null> {
    try {
      // Look for the remediation result file
      const workspaceDir = path.join(process.cwd(), "patching-workspace", remediationId);
      const resultFile = path.join(workspaceDir, "remediation-result.json");
      const content = await fs.readFile(resultFile, "utf-8");
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  async getRemediationDetailsByScanId(scanId: string): Promise<any> {
    try {
      // In a real implementation, we'd map scan IDs to remediation IDs
      // For now, return a mock response
      return {
        scanId,
        remediationId: "mock-remediation-id",
        packagesUpgraded: [],
        resultImageName: "mock-image:patched",
        message: "Scan ID mapping would be implemented in a production system",
      };
    } catch (error) {
      return null;
    }
  }

  async getRemediationContinuitySummary(fqin: string): Promise<RemediationContinuitySummary | null> {
    try {
      const history = await this.getRemediationHistory(fqin);

      if (history.length === 0) {
        return null;
      }

      const summary: RemediationContinuitySummary = {
        fqin,
        totalRemediations: history.length,
        rootPatches: history.filter(h => h.status === "completed").length,
        upstreamUpgrades: 0, // Would be calculated based on patch types
        firstRemediation: history[history.length - 1].timestamp,
        lastRemediation: history[0].timestamp,
        vulnerabilityTrends: {
          critical: { before: 0, after: 0 },
          high: { before: 0, after: 0 },
          medium: { before: 0, after: 0 },
          low: { before: 0, after: 0 },
        },
      };

      return summary;
    } catch (error) {
      return null;
    }
  }

  async listRemediationContinuitySummaries(): Promise<RemediationContinuitySummary[]> {
    try {
      const history = await this.getRemediationHistory();
      const imageMap = new Map<string, RemediationHistory[]>();

      // Group by image
      for (const entry of history) {
        if (!imageMap.has(entry.image)) {
          imageMap.set(entry.image, []);
        }
        imageMap.get(entry.image)!.push(entry);
      }

      const summaries: RemediationContinuitySummary[] = [];
      for (const [fqin, entries] of imageMap) {
        const summary = await this.getRemediationContinuitySummary(fqin);
        if (summary) {
          summaries.push(summary);
        }
      }

      return summaries;
    } catch (error) {
      return [];
    }
  }

  async listUniqueFqins(): Promise<string[]> {
    try {
      const history = await this.getRemediationHistory();
      const fqins = new Set(history.map(entry => entry.image));
      return Array.from(fqins).sort();
    } catch (error) {
      return [];
    }
  }

  async generateReport(type: "summary" | "detailed", filters?: {
    image?: string;
    dateFrom?: string;
    dateTo?: string;
  }): Promise<any> {
    try {
      const history = await this.getRemediationHistory(filters?.image);

      let filteredHistory = history;
      if (filters?.dateFrom || filters?.dateTo) {
        filteredHistory = history.filter(entry => {
          const entryDate = new Date(entry.timestamp);
          if (filters.dateFrom && entryDate < new Date(filters.dateFrom)) {
            return false;
          }
          if (filters.dateTo && entryDate > new Date(filters.dateTo)) {
            return false;
          }
          return true;
        });
      }

      if (type === "summary") {
        return {
          totalRemediations: filteredHistory.length,
          successfulRemediations: filteredHistory.filter(h => h.status === "completed").length,
          failedRemediations: filteredHistory.filter(h => h.status === "failed").length,
          totalVulnerabilitiesFixed: filteredHistory.reduce((sum, h) => sum + h.vulnerabilitiesFixed, 0),
          totalPackagesUpgraded: filteredHistory.reduce((sum, h) => sum + h.packagesUpgraded, 0),
          uniqueImagesRemediated: new Set(filteredHistory.map(h => h.image)).size,
        };
      }

      return {
        summary: await this.generateReport("summary", filters),
        remediations: filteredHistory,
      };
    } catch (error) {
      throw new Error(`Failed to generate report: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
