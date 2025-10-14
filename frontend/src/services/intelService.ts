// src/services/intelService.ts
import { httpClient } from './http';
import { api } from './api';

export interface CVEIntel {
  cve: string;
  description: string;
  cvss: number;
  exploit_refs: string[];
  updated_at: string;
}

class IntelService {
  public async getCVEIntel(cve: string): Promise<CVEIntel> {
    try {
      const response = await httpClient.get<CVEIntel>(api.intel.cve(cve));
      return response.data;
    } catch (error) {
      console.error('Failed to fetch CVE intel:', error);
      throw new Error(`Failed to fetch CVE intel: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export const intelService = new IntelService();