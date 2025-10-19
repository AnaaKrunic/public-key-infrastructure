import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CertificateRequest } from '../../models/CertificateRequest';
import { CreateCertificateRequest } from '../../models/CreateCertificateRequest';
import { KeyPair } from '../../models/KeyPair';
import { CSRStatus } from '../../models/CSRStatus';

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

  // Get pending certificate requests (for CA users) with pagination
  getPendingCertificateRequests(page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/csr/`, { params });
  }

  // Get my certificate requests (for EE users)
  getMyCertificateRequests(page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/csr/my`, { params });
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

  // Upload CSR file with private key
  uploadCSR(formData: FormData): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/csr/upload`, formData);
  }

  // Create form-based CSR with automatic key generation
  createFormBasedCSR(request: CreateCertificateRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/csr/form`, request);
  }

  // Get certificate request by ID
  getCertificateRequestById(id: string): Observable<CertificateRequest> {
    return this.http.get<CertificateRequest>(`${this.API_BASE_URL}/csr/${id}`);
  }

  // Search certificate requests
  searchCertificateRequests(query: string, page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('q', query)
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/csr/search`, { params });
  }

  // Get certificate request statistics
  getCertificateRequestStats(): Observable<any> {
    return this.http.get<any>(`${this.API_BASE_URL}/csr/stats`);
  }

  // Download CSR
  downloadCSR(id: string): Observable<Blob> {
    return this.http.get(`${this.API_BASE_URL}/csr/${id}/download`, {
      responseType: 'blob'
    });
  }

  // Get CSR details
  getCSRDetails(id: string): Observable<any> {
    return this.http.get<any>(`${this.API_BASE_URL}/csr/${id}/details`);
  }
}
