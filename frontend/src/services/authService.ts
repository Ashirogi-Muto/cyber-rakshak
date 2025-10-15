// src/services/authService.ts
import { api } from './api';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  role: string;
}

export interface User {
  id: string;
  email: string;
  username: string;
  role: string;
}

class AuthService {
  private tokenKey = 'authToken';
  private userKey = 'currentUser';

  constructor() {
    // Clear authentication data on every page load to prevent cached login
    this.clearAuthData();
  }

  private clearAuthData(): void {
    // Clear sessionStorage on page load to prevent cached login
    sessionStorage.removeItem(this.tokenKey);
    sessionStorage.removeItem(this.userKey);
  }

  public async login(credentials: LoginRequest): Promise<boolean> {
    try {
      // Hardcoded credentials for demo purposes
      const validCredentials = [
        { email: "admin@cyberrakshak.ai", password: "demo123" },
        { email: "user@example.com", password: "password123" },
        { email: "test@test.com", password: "test123" }
      ];

      // Check if provided credentials match any hardcoded credentials
      const isValid = validCredentials.some(cred => 
        cred.email === credentials.email && cred.password === credentials.password
      );

      if (isValid) {
        // Extract username from email (everything before @)
        const username = credentials.email.split('@')[0];
        
        // Create mock token and user data
        const mockToken = `mock-token-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const user: User = {
          id: '1',
          email: credentials.email,
          username: username,
          role: 'admin' // Default role for demo
        };
        
        this.setToken(mockToken);
        this.setCurrentUser(user);
        return true;
      } else {
        // Authentication failed
        return false;
      }
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  }

  public async logout(): Promise<void> {
    this.removeToken();
    this.removeCurrentUser();
  }

  public isAuthenticated(): boolean {
    return !!this.getToken();
  }

  public getToken(): string | null {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    return sessionStorage.getItem(this.tokenKey);
  }

  public getCurrentUser(): User | null {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    const userStr = sessionStorage.getItem(this.userKey);
    return userStr ? JSON.parse(userStr) : null;
  }

  private setToken(token: string): void {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    sessionStorage.setItem(this.tokenKey, token);
  }

  private setCurrentUser(user: User): void {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    sessionStorage.setItem(this.userKey, JSON.stringify(user));
  }

  private removeToken(): void {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    sessionStorage.removeItem(this.tokenKey);
  }

  private removeCurrentUser(): void {
    // Use sessionStorage instead of localStorage to prevent persistence between sessions
    sessionStorage.removeItem(this.userKey);
  }
}

export const authService = new AuthService();