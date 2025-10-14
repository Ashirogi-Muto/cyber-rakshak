// src/services/chatService.ts
import { httpClient } from './http';
import { api } from './api';

export interface ChatQueryRequest {
  report_id: string;
  query: string;
  mode?: string;
}

export interface ChatCitation {
  id: string;
  source: string;
  text_snippet: string;
  ref: string;
}

export interface ChatQueryResponse {
  answer: string;
  citations: ChatCitation[];
  confidence: number;
}

class ChatService {
  public async query(request: ChatQueryRequest): Promise<ChatQueryResponse> {
    try {
      const response = await httpClient.post<ChatQueryResponse>(api.chat.query, request);
      return response.data;
    } catch (error) {
      console.error('Chat query failed:', error);
      throw new Error(`Chat query failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export const chatService = new ChatService();