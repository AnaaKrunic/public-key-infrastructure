import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Certificate } from '../../../models/Certificate';

@Component({
  selector: 'app-all-certificates',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="container">
      <h1>All Certificates</h1>
      
      <div class="actions">
        <button (click)="refreshCertificates()" class="btn btn-primary">
          Refresh
        </button>
      </div>

      <div *ngIf="loading" class="loading">
        Loading certificates...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="certificates.length > 0" class="certificates-table">
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
            <tr *ngFor="let cert of certificates">
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
                <button (click)="viewDetails(cert)" class="btn btn-sm btn-secondary">
                  Details
                </button>
                <button (click)="revokeCertificate(cert)" class="btn btn-sm btn-danger">
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && certificates.length === 0" class="no-data">
        No certificates found.
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
  `]
})
export class AllCertificatesComponent implements OnInit {
  certificates: Certificate[] = [];
  loading = false;
  error: string | null = null;

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

  viewDetails(certificate: Certificate): void {
    // TODO: Implement certificate details modal
    console.log('View details for certificate:', certificate);
  }

  revokeCertificate(certificate: Certificate): void {
    if (confirm(`Are you sure you want to revoke certificate ${certificate.serialNumber}?`)) {
      // TODO: Implement certificate revocation
      console.log('Revoke certificate:', certificate);
    }
  }

  formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString();
  }
}
