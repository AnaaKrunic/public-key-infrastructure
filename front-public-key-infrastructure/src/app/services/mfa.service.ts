import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MfaService {
  private readonly API_URL = 'http://localhost:8080/api/mfa';

  constructor(private http: HttpClient) {}

  enableMfa(email: string): Observable<{qrImage: string, secretKey: string}> {
    return this.http.post<{qrImage: string, secretKey: string}>(`${this.API_URL}/enable`, null, {
      params: { email }
    });
  }

  verifyMfa(email: string, code: string): Observable<any> {
    return this.http.post<any>(`${this.API_URL}/verify`, null, {
      params: { email, code }
    });
  }

  getMfaStatus(email: string): Observable<{mfaEnabled: boolean}> {
    return this.http.get<{mfaEnabled: boolean}>(`${this.API_URL}/status`, {
      params: { email }
    });
  }
}
