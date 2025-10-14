// src/services/attackPathService.ts
import { httpClient } from './http';
import { api } from './api';

export interface AttackPathNode {
  id: string;
  type: string;
  label: string;
  description?: string;
  severity?: string;
}

export interface AttackPathEdge {
  from: string;
  to: string;
  desc: string;
}

export interface AttackPathResponse {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
}

class AttackPathService {
  public async getAttackPath(reportId: string): Promise<AttackPathResponse> {
    try {
      const response = await httpClient.get<AttackPathResponse>(api.attackPath.detail(reportId));
      return response.data;
    } catch (error) {
      console.error('Failed to fetch attack path:', error);
      throw new Error(`Failed to fetch attack path: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export const attackPathService = new AttackPathService();