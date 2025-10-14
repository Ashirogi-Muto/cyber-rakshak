// src/services/scanService.ts
import { httpClient } from './http';
import { api } from './api';

export interface ScanRequest {
  target: string;
  profile?: string;
  tools?: string[];
}

export interface ScanResult {
  tool: string;
  result: any;
}

export interface StartScanResponse {
  message: string;
  results: ScanResult[];
  report_id?: string;
}

export interface ScanStatusResponse {
  job_id: string;
  status: string;
  progress: string;
}

class ScanService {
  public async startScan(request: ScanRequest): Promise<StartScanResponse> {
    try {
      console.log("scanService.startScan called with request:", request);
      console.log("API endpoint:", api.scans.start);
      
      const response = await httpClient.post<StartScanResponse>(api.scans.start, request);
      console.log("scanService.startScan response:", response);
      
      return response.data;
    } catch (error: any) {
      console.error('Scan failed in scanService:', error);
      console.error('Error response:', error.response);
      
      // If there's a response from the server, include that in the error message
      if (error.response) {
        throw new Error(`Failed to start scan: ${error.response.status} - ${error.response.statusText}`);
      } else if (error.request) {
        throw new Error(`Failed to start scan: No response received from server`);
      } else {
        throw new Error(`Failed to start scan: ${error.message}`);
      }
    }
  }

  public async getScanStatus(jobId: string): Promise<ScanStatusResponse> {
    try {
      const response = await httpClient.get<ScanStatusResponse>(api.scans.status(jobId));
      return response.data;
    } catch (error) {
      console.error('Failed to get scan status:', error);
      throw new Error(`Failed to get scan status: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export const scanService = new ScanService();