import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Certificate } from '../../models/Certificate';
import { IssueCertificateRequest } from '../../models/IssueCertificateRequest';
import { DownloadCertificateRequest } from '../../models/DownloadCertificateRequest';
import { RevokeCertificateRequest } from '../../models/RevokeCertificateRequest';
import { CreateCaUser } from '../../models/CreateCaUser';
import { CaUser } from '../../models/CaUser';
import { CertificateType } from '../../models/CertificateType';
import { CertificateStatus } from '../../models/CertificateStatus';

@Injectable({
  providedIn: 'root'
})
export class CertificatesService {
  private readonly API_BASE_URL = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  // Get all certificates with pagination and filtering
  getAllCertificates(page: number = 0, size: number = 10, type?: CertificateType, status?: CertificateStatus): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());
    
    if (type) {
      params = params.set('type', type);
    }
    if (status) {
      params = params.set('status', status);
    }

    return this.http.get<any>(`${this.API_BASE_URL}/certificates/get-all`, { params });
  }

  // Get all valid signing certificates
  getAllValidSigningCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-all-valid-signing`);
  }

  // Get valid signing certificates for current CA user (organization-specific)
  getMyValidSigningCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-my-valid-certificates`);
  }

  // Get valid signing certificates for current user's organization
  getOrganizationSigningCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-organization-signing-certificates`);
  }

  // Get my certificates with pagination
  getMyCertificates(page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/certificates/get-my-certificates`, { params });
  }

  // Get my valid certificates
  getMyValidCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-my-valid-certificates`);
  }

  // Get valid CA users for certificate requests
  getValidCaUsers(): Observable<CaUser[]> {
    return this.http.get<CaUser[]>(`${this.API_BASE_URL}/users/get-valid-ca-users`);
  }

  // Download certificate with password
  downloadCertificate(request: DownloadCertificateRequest): Observable<Blob> {
    return this.http.post(`${this.API_BASE_URL}/certificates/download`, request, {
      responseType: 'blob'
    });
  }

  // Get certificates signed by me (for CA users) with pagination
  getCertificatesSignedByMe(page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/certificates/get-certificates-signed-by-me`, { params });
  }

  // Issue a certificate
  issueCertificate(request: IssueCertificateRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/certificates/issue`, request);
  }


  // Download certificate in specific format
  downloadCertificateInFormat(serialNumber: string, format: string = 'PEM', password?: string): Observable<Blob> {
    let url = `${this.API_BASE_URL}/certificates/download/${serialNumber}?format=${format}`;
    if (password) {
      url += `&password=${encodeURIComponent(password)}`;
    }
    return this.http.get(url, { responseType: 'blob' });
  }

  // Revoke certificate
  revokeCertificate(request: RevokeCertificateRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/crl/revoke`, request);
  }

  // Add certificate to CA user (Admin only)
  addCertificateToCaUser(caUserId: string, certificateSerialNumber: string): Observable<any> {
    return this.http.put(`${this.API_BASE_URL}/certificates/add-certificate-to-ca-user`, {
      caUserId,
      newCertificateSerialNumber: certificateSerialNumber
    });
  }

  // Get signing certificates that CA user doesn't have (Admin only)
  getSigningCertificatesCaUserDoesntHave(caUserId: string): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-signing-ca-doesnt-have/${caUserId}`);
  }

  // Get certificate by ID
  getCertificateById(id: string): Observable<Certificate> {
    return this.http.get<Certificate>(`${this.API_BASE_URL}/certificates/${id}`);
  }

  // Get certificate by serial number
  getCertificateBySerialNumber(serialNumber: string): Observable<Certificate> {
    return this.http.get<Certificate>(`${this.API_BASE_URL}/certificates/serial/${serialNumber}`);
  }

  // Get certificate chain
  getCertificateChain(serialNumber: string): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/${serialNumber}/chain`);
  }

  // Validate certificate
  validateCertificate(serialNumber: string): Observable<any> {
    return this.http.get<any>(`${this.API_BASE_URL}/certificates/${serialNumber}/validate`);
  }

  // Search certificates
  searchCertificates(query: string, page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('q', query)
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/certificates/search`, { params });
  }

  // Get certificate statistics
  getCertificateStats(): Observable<any> {
    return this.http.get<any>(`${this.API_BASE_URL}/certificates/stats`);
  }

  // Get expiring certificates
  getExpiringCertificates(days: number = 30): Observable<Certificate[]> {
    const params = new HttpParams().set('days', days.toString());
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/expiring`, { params });
  }

  // Get revoked certificates with pagination
  getRevokedCertificates(page: number = 0, size: number = 10): Observable<any> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(`${this.API_BASE_URL}/certificates/revoked`, { params });
  }

  // Create root certificate (self-signed)
  createRootCertificate(request: any): Observable<Certificate> {
    return this.http.post<Certificate>(`${this.API_BASE_URL}/certificates/root`, request);
  }

  // Create intermediate certificate
  createIntermediateCertificate(request: any): Observable<Certificate> {
    return this.http.post<Certificate>(`${this.API_BASE_URL}/certificates/intermediate`, request);
  }

  // Create end entity certificate
  createEndEntityCertificate(request: any): Observable<Certificate> {
    return this.http.post<Certificate>(`${this.API_BASE_URL}/certificates/end-entity`, request);
  }

  // Generate PKCS12 file for certificate
  generatePKCS12File(request: { certificateSerialNumber: string; password: string }): Observable<Blob> {
    return this.http.post(`${this.API_BASE_URL}/certificates/download`, request, {
      responseType: 'blob'
    });
  }
}