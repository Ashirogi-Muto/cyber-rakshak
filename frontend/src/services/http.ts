// src/services/http.ts
import { api } from './api';
import { authService } from './authService';

interface HttpResponse<T> {
  data: T;
  status: number;
  statusText: string;
  headers: Headers;
}

class HttpClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;

  constructor(baseUrl: string = '') {
    this.baseUrl = baseUrl;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
    };
  }

  private async request<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<HttpResponse<T>> {
    const fullUrl = this.baseUrl + url;
    console.log("Making HTTP request:", { fullUrl, options });
    
    // Add authorization header if user is authenticated
    const token = authService.getToken();
    console.log("Auth token:", token ? "Present" : "Missing");
    
    const headers = {
      ...this.defaultHeaders,
      ...options.headers,
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };

    const config: RequestInit = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(fullUrl, config);
      console.log("HTTP response:", response);
      
      // Handle empty responses
      let data: T;
      if (response.status !== 204) {
        const text = await response.text();
        console.log("Response text:", text);
        data = text ? JSON.parse(text) : null;
      } else {
        data = null as unknown as T;
      }

      return {
        data,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      };
    } catch (error) {
      console.error(`HTTP request failed: ${fullUrl}`, error);
      throw new Error(`Network error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async get<T>(url: string, headers: Record<string, string> = {}): Promise<HttpResponse<T>> {
    return this.request<T>(url, { method: 'GET', headers });
  }

  public async post<T>(url: string, body?: any, headers: Record<string, string> = {}): Promise<HttpResponse<T>> {
    return this.request<T>(url, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
      headers,
    });
  }

  public async put<T>(url: string, body: any, headers: Record<string, string> = {}): Promise<HttpResponse<T>> {
    return this.request<T>(url, {
      method: 'PUT',
      body: JSON.stringify(body),
      headers,
    });
  }

  public async delete<T>(url: string, headers: Record<string, string> = {}): Promise<HttpResponse<T>> {
    return this.request<T>(url, { method: 'DELETE', headers });
  }
}

// Create a singleton instance
export const httpClient = new HttpClient();