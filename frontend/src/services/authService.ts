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

  public async login(credentials: LoginRequest): Promise<boolean> {
    try {
      // Extract username from email (everything before @)
      const username = credentials.email.split('@')[0];
      
      // Try to authenticate with backend
      const response = await fetch(`${api.auth.login}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          password: credentials.password
        }),
      });

      if (response.ok) {
        const data: LoginResponse = await response.json();
        
        // Store token and user data
        const user: User = {
          id: '1',
          email: credentials.email,
          username: username,
          role: data.role
        };
        
        this.setToken(data.access_token);
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