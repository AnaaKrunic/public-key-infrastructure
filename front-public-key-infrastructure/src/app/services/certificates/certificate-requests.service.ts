import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CertificateRequest } from '../../models/CertificateRequest';
import { CreateCertificateRequest } from '../../models/CreateCertificateRequest';
import { KeyPair } from '../../models/KeyPair';

@Injectable({
  providedIn: 'root'
})
export class CertificateRequestsService {
  private readonly API_BASE_URL = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  // Create certificate request (form-based)
  createCertificateRequest(request: CreateCertificateRequest): Observable<KeyPair> {
    return this.http.post<KeyPair>(`${this.API_BASE_URL}/csr/form`, request);
  }

  // Get pending certificate requests (for CA users)
  getPendingCertificateRequests(): Observable<CertificateRequest[]> {
    return this.http.get<CertificateRequest[]>(`${this.API_BASE_URL}/csr/`);
  }

  // Approve certificate request
  approveCertificateRequest(requestId: string, validityDays: number, templateId?: number): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/csr/approve`, {
      requestId,
      validityDays,
      templateId
    });
  }

  // Reject certificate request
  rejectCertificateRequest(requestId: string): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/csr/reject`, requestId);
  }
}
