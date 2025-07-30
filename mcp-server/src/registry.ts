import { promises as fs } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

export interface RegistryCredentials {
  id: string;
  name: string;
  registryUrl: string;
  username: string;
  createdAt: string;
  lastUsed?: string;
}

export interface RegistryIntegration {
  id: string;
  name: string;
  registryUrl: string;
  username: string;
  password: string;
  createdAt: string;
}

export class RegistryManager {
  private credentialsFile: string;

  constructor() {
    this.credentialsFile = path.join(process.cwd(), "registry-credentials.json");
    this.ensureCredentialsFile();
  }

  private async ensureCredentialsFile() {
    try {
      await fs.access(this.credentialsFile);
    } catch (error) {
      // File doesn't exist, create it
      await fs.writeFile(this.credentialsFile, JSON.stringify([], null, 2));
    }
  }

  async listCredentials(): Promise<RegistryCredentials[]> {
    try {
      const content = await fs.readFile(this.credentialsFile, "utf-8");
      const credentials: RegistryIntegration[] = JSON.parse(content);

      // Return credentials without passwords
      return credentials.map(cred => ({
        id: cred.id,
        name: cred.name,
        registryUrl: cred.registryUrl,
        username: cred.username,
        createdAt: cred.createdAt,
        lastUsed: undefined, // Would track usage in a real implementation
      }));
    } catch (error) {
      return [];
    }
  }

  async createIntegration(integration: {
    registryUrl: string;
    username: string;
    password: string;
    name: string;
  }): Promise<RegistryCredentials> {
    const id = uuidv4();
    const newIntegration: RegistryIntegration = {
      id,
      name: integration.name,
      registryUrl: integration.registryUrl,
      username: integration.username,
      password: integration.password,
      createdAt: new Date().toISOString(),
    };

    try {
      const content = await fs.readFile(this.credentialsFile, "utf-8");
      const credentials: RegistryIntegration[] = JSON.parse(content);
      credentials.push(newIntegration);

      await fs.writeFile(this.credentialsFile, JSON.stringify(credentials, null, 2));

      // Return without password
      return {
        id: newIntegration.id,
        name: newIntegration.name,
        registryUrl: newIntegration.registryUrl,
        username: newIntegration.username,
        createdAt: newIntegration.createdAt,
      };
    } catch (error) {
      throw new Error(`Failed to create registry integration: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getCredentials(id: string): Promise<RegistryIntegration | null> {
    try {
      const content = await fs.readFile(this.credentialsFile, "utf-8");
      const credentials: RegistryIntegration[] = JSON.parse(content);
      return credentials.find(cred => cred.id === id) || null;
    } catch (error) {
      return null;
    }
  }

  async deleteCredentials(id: string): Promise<boolean> {
    try {
      const content = await fs.readFile(this.credentialsFile, "utf-8");
      const credentials: RegistryIntegration[] = JSON.parse(content);
      const filteredCredentials = credentials.filter(cred => cred.id !== id);

      if (filteredCredentials.length === credentials.length) {
        return false; // No credentials were removed
      }

      await fs.writeFile(this.credentialsFile, JSON.stringify(filteredCredentials, null, 2));
      return true;
    } catch (error) {
      return false;
    }
  }

  async updateLastUsed(id: string): Promise<void> {
    try {
      const content = await fs.readFile(this.credentialsFile, "utf-8");
      const credentials: RegistryIntegration[] = JSON.parse(content);
      const credential = credentials.find(cred => cred.id === id);

      if (credential) {
        // In a real implementation, we'd track last used time
        await fs.writeFile(this.credentialsFile, JSON.stringify(credentials, null, 2));
      }
    } catch (error) {
      // Ignore errors for usage tracking
    }
  }

  async testConnection(id: string): Promise<boolean> {
    const credentials = await this.getCredentials(id);
    if (!credentials) {
      return false;
    }

    try {
      // In a real implementation, we would test the registry connection
      // For now, just return true if credentials exist
      return true;
    } catch (error) {
      return false;
    }
  }
}
