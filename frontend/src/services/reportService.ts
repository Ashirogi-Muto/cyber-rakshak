// src/services/reportService.ts
import { httpClient } from './http';
import { api } from './api';

export interface ReportSummary {
  report_id: string;
  target: string;
  scan_timestamp: string;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface Vulnerability {
  cve?: string;
  severity: string;
  title: string;
  description?: string;
  cvss?: number;
  reference?: string;
}

export interface ReportDetail {
  report_id: string;
  target: string;
  vulnerabilities: Vulnerability[];
}

export interface UploadReportRequest {
  report_data: any;
}

export interface UploadReportResponse {
  message: string;
  report_id: string;
}

class ReportService {
  public async getReportsList(): Promise<ReportSummary[]> {
    try {
      const response = await httpClient.get<ReportSummary[]>(api.reports.list);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch reports list:', error);
      throw new Error(`Failed to fetch reports: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async getReportDetails(reportId: string): Promise<ReportDetail> {
    try {
      const response = await httpClient.get<ReportDetail>(api.reports.detail(reportId));
      return response.data;
    } catch (error) {
      console.error('Failed to fetch report details:', error);
      throw new Error(`Failed to fetch report details: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async uploadReport(request: UploadReportRequest): Promise<UploadReportResponse> {
    try {
      const response = await httpClient.post<UploadReportResponse>(api.reports.upload, request);
      return response.data;
    } catch (error) {
      console.error('Failed to upload report:', error);
      throw new Error(`Failed to upload report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export const reportService = new ReportService();