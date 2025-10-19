import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Certificate } from '../../../models/Certificate';
import { RevokeCertificateRequest } from '../../../models/RevokeCertificateRequest';
import { RevocationReason } from '../../../models/RevocationReason';

@Component({
  selector: 'app-all-certificates',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>All Certificates</h1>
      
      <div class="actions">
        <button (click)="refreshCertificates()" class="btn btn-primary">
          Refresh
        </button>
        <div class="search-filter">
          <input 
            type="text" 
            [(ngModel)]="searchTerm" 
            (input)="filterCertificates()"
            placeholder="Search certificates..."
            class="search-input">
          <select [(ngModel)]="statusFilter" (change)="filterCertificates()" class="filter-select">
            <option value="">All Statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="EXPIRED">Expired</option>
            <option value="REVOKED">Revoked</option>
            <option value="DORMANT">Dormant</option>
          </select>
          <select [(ngModel)]="typeFilter" (change)="filterCertificates()" class="filter-select">
            <option value="">All Types</option>
            <option value="ROOT">Root CA</option>
            <option value="INTERMEDIATE">Intermediate CA</option>
            <option value="END_ENTITY">End Entity</option>
          </select>
        </div>
      </div>

      <div *ngIf="loading" class="loading">
        Loading certificates...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="filteredCertificates.length > 0" class="certificates-table">
        <table>
          <thead>
            <tr>
              <th>Serial Number</th>
              <th>Subject</th>
              <th>Issuer</th>
              <th>Type</th>
              <th>Valid From</th>
              <th>Valid To</th>
              <th>Status</th>
              <th>Owner</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let cert of filteredCertificates">
              <td>{{ cert.serialNumber }}</td>
              <td>{{ cert.subjectCN }}</td>
              <td>{{ cert.issuerCN }}</td>
              <td>
                <span [class]="'type-' + cert.certificateType.toLowerCase()">
                  {{ cert.certificateType }}
                </span>
              </td>
              <td>{{ formatDate(cert.validFrom) }}</td>
              <td>{{ formatDate(cert.validTo) }}</td>
              <td>
                <span [class]="'status-' + cert.status.toLowerCase()">
                  {{ cert.status }}
                </span>
              </td>
              <td>{{ cert.owner?.firstName }} {{ cert.owner?.lastName }}</td>
              <td>
                <div class="action-buttons">
                  <button (click)="downloadCertificate(cert, 'PEM')" class="btn btn-sm btn-info" title="Download PEM">
                    PEM
                  </button>
                  <button (click)="downloadCertificate(cert, 'PKCS12')" class="btn btn-sm btn-info" title="Download PKCS12">
                    PKCS12
                  </button>
                  <button (click)="viewDetails(cert)" class="btn btn-sm btn-secondary" title="View Details">
                    Details
                  </button>
                  <button 
                    (click)="showRevokeModal(cert)" 
                    class="btn btn-sm btn-danger" 
                    title="Revoke Certificate"
                    [disabled]="cert.status === 'REVOKED'">
                    Revoke
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && filteredCertificates.length === 0" class="no-data">
        No certificates found.
      </div>

      <!-- Revocation Modal -->
      <div *ngIf="showRevokeModalFlag" class="modal-overlay" (click)="closeRevokeModal()">
        <div class="modal" (click)="$event.stopPropagation()">
          <h3>Revoke Certificate</h3>
          <p><strong>Serial Number:</strong> {{ selectedCertificate?.serialNumber }}</p>
          <p><strong>Subject:</strong> {{ selectedCertificate?.subjectCN }}</p>
          
          <form (ngSubmit)="revokeCertificate()" #revokeForm="ngForm">
            <div class="form-group">
              <label for="revocationReason">Revocation Reason *</label>
              <select 
                id="revocationReason" 
                name="revocationReason" 
                [(ngModel)]="revokeRequest.revocationReason" 
                required
                class="form-control">
                <option value="">Select a reason</option>
                <option *ngFor="let reason of revocationReasons" [value]="reason">
                  {{ reason }}
                </option>
              </select>
            </div>
            
            
            <div class="form-actions">
              <button type="submit" [disabled]="!revokeForm.form.valid || revoking" class="btn btn-danger">
                {{ revoking ? 'Revoking...' : 'Revoke Certificate' }}
              </button>
              <button type="button" (click)="closeRevokeModal()" class="btn btn-secondary">
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- Certificate Details Modal -->
      <div *ngIf="showDetailsModal" class="modal-overlay" (click)="closeDetailsModal()">
        <div class="modal large-modal" (click)="$event.stopPropagation()">
          <h3>Certificate Details</h3>
          <div *ngIf="selectedCertificate" class="certificate-details">
            <div class="detail-section">
              <h4>Basic Information</h4>
              <div class="detail-grid">
                <div class="detail-item">
                  <label>Serial Number:</label>
                  <span>{{ selectedCertificate.serialNumber }}</span>
                </div>
                <div class="detail-item">
                  <label>Status:</label>
                  <span [class]="'status-' + selectedCertificate.status.toLowerCase()">
                    {{ selectedCertificate.status }}
                  </span>
                </div>
                <div class="detail-item">
                  <label>Type:</label>
                  <span [class]="'type-' + selectedCertificate.certificateType.toLowerCase()">
                    {{ selectedCertificate.certificateType }}
                  </span>
                </div>
                <div class="detail-item">
                  <label>Can Sign:</label>
                  <span>{{ selectedCertificate.canSign ? 'Yes' : 'No' }}</span>
                </div>
              </div>
            </div>
            
            <div class="detail-section">
              <h4>Validity Period</h4>
              <div class="detail-grid">
                <div class="detail-item">
                  <label>Valid From:</label>
                  <span>{{ formatDate(selectedCertificate.validFrom) }}</span>
                </div>
                <div class="detail-item">
                  <label>Valid To:</label>
                  <span>{{ formatDate(selectedCertificate.validTo) }}</span>
                </div>
                <div class="detail-item" *ngIf="selectedCertificate.revocationDate">
                  <label>Revoked On:</label>
                  <span>{{ formatDate(selectedCertificate.revocationDate) }}</span>
                </div>
                <div class="detail-item" *ngIf="selectedCertificate.revocationReason">
                  <label>Revocation Reason:</label>
                  <span>{{ selectedCertificate.revocationReason }}</span>
                </div>
              </div>
            </div>
            
            <div class="detail-section">
              <h4>Subject Information</h4>
              <div class="detail-grid">
                <div class="detail-item">
                  <label>Common Name:</label>
                  <span>{{ selectedCertificate.subjectCN }}</span>
                </div>
                <div class="detail-item">
                  <label>Organization:</label>
                  <span>{{ selectedCertificate.subjectO }}</span>
                </div>
                <div class="detail-item">
                  <label>Organizational Unit:</label>
                  <span>{{ selectedCertificate.subjectOU }}</span>
                </div>
                <div class="detail-item">
                  <label>Email:</label>
                  <span>{{ selectedCertificate.subjectE }}</span>
                </div>
                <div class="detail-item">
                  <label>Country:</label>
                  <span>{{ selectedCertificate.subjectC }}</span>
                </div>
              </div>
            </div>
            
            <div class="detail-section">
              <h4>Issuer Information</h4>
              <div class="detail-grid">
                <div class="detail-item">
                  <label>Issuer CN:</label>
                  <span>{{ selectedCertificate.issuerCN }}</span>
                </div>
                <div class="detail-item">
                  <label>Issuer Organization:</label>
                  <span>{{ selectedCertificate.issuerO }}</span>
                </div>
              </div>
            </div>
            
            <div class="detail-section" *ngIf="selectedCertificate.keyUsage">
              <h4>Key Usage</h4>
              <p>{{ selectedCertificate.keyUsage }}</p>
            </div>
            
            <div class="detail-section" *ngIf="selectedCertificate.extendedKeyUsage">
              <h4>Extended Key Usage</h4>
              <p>{{ selectedCertificate.extendedKeyUsage }}</p>
            </div>
          </div>
          
          <div class="form-actions">
            <button (click)="closeDetailsModal()" class="btn btn-secondary">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .actions {
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }

    .search-filter {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .search-input, .filter-select {
      padding: 8px 12px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }

    .search-input {
      min-width: 200px;
    }

    .filter-select {
      min-width: 120px;
    }

    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }

    .btn-primary {
      background-color: #007bff;
      color: white;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-info {
      background-color: #17a2b8;
      color: white;
    }

    .btn-sm {
      padding: 4px 8px;
      font-size: 11px;
      margin-right: 5px;
    }

    .loading, .error, .no-data {
      text-align: center;
      padding: 20px;
      font-size: 16px;
    }

    .error {
      color: #dc3545;
    }

    .certificates-table {
      margin-top: 20px;
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      min-width: 1000px;
    }

    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }

    th {
      background-color: #f8f9fa;
      font-weight: 600;
    }

    tr:hover {
      background-color: #f5f5f5;
    }

    .type-root {
      color: #6f42c1;
      font-weight: bold;
    }

    .type-intermediate {
      color: #fd7e14;
      font-weight: bold;
    }

    .type-end_entity {
      color: #20c997;
      font-weight: bold;
    }

    .status-active {
      color: #28a745;
      font-weight: bold;
    }

    .status-expired {
      color: #dc3545;
      font-weight: bold;
    }

    .status-revoked {
      color: #dc3545;
      font-weight: bold;
    }

    .action-buttons {
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
    }

    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }

    .modal {
      background: white;
      padding: 20px;
      border-radius: 8px;
      max-width: 500px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
    }

    .large-modal {
      max-width: 800px;
    }

    .form-group {
      margin-bottom: 15px;
    }

    .form-group label {
      display: block;
      margin-bottom: 5px;
      font-weight: 600;
    }

    .form-control {
      width: 100%;
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }

    .form-text {
      color: #6c757d;
      font-size: 12px;
      margin-top: 5px;
    }

    .form-actions {
      margin-top: 20px;
      display: flex;
      gap: 10px;
      justify-content: flex-end;
    }

    .certificate-details {
      max-height: 60vh;
      overflow-y: auto;
    }

    .detail-section {
      margin-bottom: 20px;
      padding-bottom: 15px;
      border-bottom: 1px solid #eee;
    }

    .detail-section:last-child {
      border-bottom: none;
    }

    .detail-section h4 {
      margin: 0 0 10px 0;
      color: #333;
      font-size: 16px;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 10px;
    }

    .detail-item {
      display: flex;
      flex-direction: column;
    }

    .detail-item label {
      font-weight: 600;
      color: #666;
      font-size: 12px;
      margin-bottom: 2px;
    }

    .detail-item span {
      color: #333;
      font-size: 14px;
    }
  `]
})
export class AllCertificatesComponent implements OnInit {
  certificates: Certificate[] = [];
  filteredCertificates: Certificate[] = [];
  loading = false;
  error: string | null = null;
  
  // Search and filter
  searchTerm = '';
  statusFilter = '';
  typeFilter = '';
  
  // Modals
  showRevokeModalFlag = false;
  showDetailsModal = false;
  selectedCertificate: Certificate | null = null;
  
  // Revocation
  revoking = false;
  revokeRequest: RevokeCertificateRequest = {
    serialNumber: '',
    revocationReason: RevocationReason.UNSPECIFIED
  };
  revocationReasons = Object.values(RevocationReason);

  constructor(private certificatesService: CertificatesService) {}

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.error = null;

    this.certificatesService.getAllCertificates().subscribe({
      next: (certs) => {
        this.certificates = certs;
        this.filteredCertificates = certs;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load certificates';
        this.loading = false;
        console.error('Error loading certificates:', err);
      }
    });
  }

  refreshCertificates(): void {
    this.loadCertificates();
  }

  filterCertificates(): void {
    this.filteredCertificates = this.certificates.filter(cert => {
      const matchesSearch = !this.searchTerm || 
        cert.serialNumber.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        cert.subjectCN.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        cert.issuerCN.toLowerCase().includes(this.searchTerm.toLowerCase());
      
      const matchesStatus = !this.statusFilter || cert.status === this.statusFilter;
      const matchesType = !this.typeFilter || cert.certificateType === this.typeFilter;
      
      return matchesSearch && matchesStatus && matchesType;
    });
  }

  downloadCertificate(certificate: Certificate, format: 'PEM' | 'PKCS12'): void {
    if (format === 'PEM') {
      this.downloadPEMCertificate(certificate);
    } else if (format === 'PKCS12') {
      this.downloadPKCS12Certificate(certificate);
    }
  }

  private downloadPEMCertificate(certificate: Certificate): void {
    const blob = new Blob([certificate.certificateData || ''], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `certificate_${certificate.serialNumber}.pem`;
    link.click();
    window.URL.revokeObjectURL(url);
  }

  private downloadPKCS12Certificate(certificate: Certificate): void {
    const request = {
      certificateSerialNumber: certificate.serialNumber,
      password: 'changeit' // Default password, in production this should be user-provided
    };

    this.certificatesService.generatePKCS12File(request).subscribe({
      next: (blob) => {
        // Create download link directly from blob
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `certificate_${certificate.serialNumber}.p12`;
        link.click();
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Error downloading PKCS12:', err);
        alert('Failed to download PKCS12 file');
      }
    });
  }

  viewDetails(certificate: Certificate): void {
    this.selectedCertificate = certificate;
    this.showDetailsModal = true;
  }

  closeDetailsModal(): void {
    this.showDetailsModal = false;
    this.selectedCertificate = null;
  }

  showRevokeModal(certificate: Certificate): void {
    this.selectedCertificate = certificate;
    this.revokeRequest = {
      serialNumber: certificate.serialNumber,
      revocationReason: RevocationReason.UNSPECIFIED
    };
    this.showRevokeModalFlag = true;
  }

  closeRevokeModal(): void {
    this.showRevokeModalFlag = false;
    this.selectedCertificate = null;
    this.revokeRequest = {
      serialNumber: '',
      revocationReason: RevocationReason.UNSPECIFIED
    };
  }

  revokeCertificate(): void {
    if (!this.selectedCertificate) return;

    this.revoking = true;
    
    this.certificatesService.revokeCertificate(this.revokeRequest).subscribe({
      next: () => {
        this.revoking = false;
        this.closeRevokeModal();
        this.loadCertificates(); // Refresh the list
        alert('Certificate revoked successfully');
      },
      error: (err) => {
        this.revoking = false;
        console.error('Error revoking certificate:', err);
        alert('Failed to revoke certificate');
      }
    });
  }

  formatDate(dateString: string): string {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'N/A';
      return date.toLocaleDateString();
    } catch (error) {
      return 'N/A';
    }
  }
}
