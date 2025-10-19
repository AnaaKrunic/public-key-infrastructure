import { Component, OnInit, inject } from '@angular/core';
import { CommonModule, DatePipe, NgIf } from '@angular/common';
import { MatTable, MatTableDataSource, MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatHeaderCell, MatHeaderCellDef, MatCell, MatCellDef, MatColumnDef } from '@angular/material/table';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { DialogService } from '../../../services/dialog/dialog.service';
import { Certificate } from '../../../models/Certificate';
import { CertificateDetailsDialogComponent } from '../../common/certificate-details-dialog/certificate-details-dialog.component';

@Component({
  selector: 'app-signed-certificates',
  standalone: true,
  imports: [
    CommonModule,
    MatTable,
    MatHeaderRow,
    MatHeaderRowDef,
    MatRow,
    MatRowDef,
    MatHeaderCell,
    MatHeaderCellDef,
    MatCell,
    MatCellDef,
    MatColumnDef,
    MatProgressSpinner,
    NgIf,
    DatePipe
  ],
  template: `
    <div class="container">
      <h1>Certificates Signed by Me</h1>
      
      <div *ngIf="loading" class="loading">
        <mat-spinner></mat-spinner>
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="!loading && !error" class="table-container">
        <mat-table [dataSource]="certificatesDataSource" class="certificates-table">
          <ng-container matColumnDef="issuedTo">
            <mat-header-cell *matHeaderCellDef>Issued to (DN)</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <div class="dn-info">
                <div class="dn-line" *ngIf="certificate.subjectCN"><strong>CN:</strong> {{ certificate.subjectCN }}</div>
                <div class="dn-line" *ngIf="certificate.subjectO"><strong>O:</strong> {{ certificate.subjectO }}</div>
                <div class="dn-line" *ngIf="certificate.subjectOU"><strong>OU:</strong> {{ certificate.subjectOU }}</div>
                <div class="dn-line" *ngIf="certificate.subjectE"><strong>E:</strong> {{ certificate.subjectE }}</div>
                <div class="dn-line" *ngIf="certificate.subjectC"><strong>C:</strong> {{ certificate.subjectC }}</div>
                <div class="dn-line" *ngIf="certificate.subjectL"><strong>L:</strong> {{ certificate.subjectL }}</div>
                <div class="dn-line" *ngIf="certificate.subjectST"><strong>ST:</strong> {{ certificate.subjectST }}</div>
              </div>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="issuedBy">
            <mat-header-cell *matHeaderCellDef>Issued by (DN)</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <div class="dn-info">
                <div class="dn-line" *ngIf="certificate.issuerCN"><strong>CN:</strong> {{ certificate.issuerCN }}</div>
                <div class="dn-line" *ngIf="certificate.issuerO"><strong>O:</strong> {{ certificate.issuerO }}</div>
                <div class="dn-line" *ngIf="certificate.issuerOU"><strong>OU:</strong> {{ certificate.issuerOU }}</div>
                <div class="dn-line" *ngIf="certificate.issuerE"><strong>E:</strong> {{ certificate.issuerE }}</div>
                <div class="dn-line" *ngIf="certificate.issuerC"><strong>C:</strong> {{ certificate.issuerC }}</div>
                <div class="dn-line" *ngIf="certificate.issuerL"><strong>L:</strong> {{ certificate.issuerL }}</div>
                <div class="dn-line" *ngIf="certificate.issuerST"><strong>ST:</strong> {{ certificate.issuerST }}</div>
              </div>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="status">
            <mat-header-cell *matHeaderCellDef>Status</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <span [class]="'status-' + certificate.status.toLowerCase()">
                {{ certificate.status }}
              </span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="validFrom">
            <mat-header-cell *matHeaderCellDef>Valid from</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              {{ certificate.validFrom | date }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="validUntil">
            <mat-header-cell *matHeaderCellDef>Valid until</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              {{ certificate.validTo | date }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="certificateType">
            <mat-header-cell *matHeaderCellDef>Type</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <span [class]="'type-' + certificate.certificateType.toLowerCase()">
                {{ certificate.certificateType }}
              </span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="serialNumber">
            <mat-header-cell *matHeaderCellDef>Serial Number</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <span class="serial-number">{{ certificate.serialNumber }}</span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="actions">
            <mat-header-cell *matHeaderCellDef>Actions</mat-header-cell>
            <mat-cell *matCellDef="let certificate">
              <div class="action-buttons">
                <button 
                  (click)="openCertificateDetails(certificate)" 
                  class="btn btn-sm btn-secondary"
                  title="View Details">
                  Details
                </button>
                <button 
                  (click)="downloadCertificate(certificate)" 
                  class="btn btn-sm btn-info"
                  title="Download Certificate">
                  Download
                </button>
              </div>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="displayedColumns"></mat-header-row>
          <mat-row *matRowDef="let row; columns: displayedColumns;"></mat-row>
        </mat-table>

        <div *ngIf="certificates.length === 0" class="no-data">
          No certificates found.
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

    .loading {
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 40px;
    }

    .error, .no-data {
      text-align: center;
      padding: 20px;
      font-size: 16px;
    }

    .error {
      color: #dc3545;
    }

    .table-container {
      margin-top: 20px;
      overflow-x: auto;
    }

    .certificates-table {
      width: 100%;
      min-width: 1000px;
    }

    /* Column-specific styling */
    .mat-column-issuedTo {
      min-width: 200px;
      max-width: 300px;
    }

    .mat-column-issuedBy {
      min-width: 200px;
      max-width: 300px;
    }

    .mat-column-status {
      min-width: 100px;
      max-width: 120px;
    }

    .mat-column-validFrom {
      min-width: 120px;
      max-width: 150px;
    }

    .mat-column-validUntil {
      min-width: 120px;
      max-width: 150px;
    }

    .mat-column-certificateType {
      min-width: 100px;
      max-width: 130px;
    }

    .mat-column-serialNumber {
      min-width: 150px;
      max-width: 200px;
    }

    .mat-column-actions {
      min-width: 150px;
      max-width: 180px;
    }

    /* Cell content styling */
    .mat-cell {
      word-wrap: break-word;
      word-break: break-all;
      white-space: normal;
      padding: 8px 12px;
      vertical-align: top;
    }

    .mat-header-cell {
      padding: 12px;
      font-weight: 600;
      background-color: #f5f5f5;
    }

    .serial-number {
      font-family: monospace;
      font-size: 11px;
      background-color: #f8f9fa;
      padding: 2px 6px;
      border-radius: 3px;
      display: inline-block;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .status-active {
      color: #28a745;
      font-weight: bold;
      padding: 4px 8px;
      background-color: #d4edda;
      border-radius: 4px;
      display: inline-block;
    }

    .status-expired {
      color: #dc3545;
      font-weight: bold;
      padding: 4px 8px;
      background-color: #f8d7da;
      border-radius: 4px;
      display: inline-block;
    }

    .status-revoked {
      color: #dc3545;
      font-weight: bold;
      padding: 4px 8px;
      background-color: #f8d7da;
      border-radius: 4px;
      display: inline-block;
    }

    .no-data {
      text-align: center;
      padding: 40px;
      color: #666;
    }

    /* Action buttons styling */
    .action-buttons {
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
    }

    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }

    .btn-sm {
      padding: 4px 8px;
      font-size: 11px;
      margin-right: 5px;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-info {
      background-color: #17a2b8;
      color: white;
    }

    /* Responsive design */
    @media (max-width: 1200px) {
      .container {
        padding: 10px;
      }
      
      .certificates-table {
        min-width: 800px;
      }
    }

    @media (max-width: 768px) {
      .container {
        padding: 5px;
      }
      
      .certificates-table {
        min-width: 600px;
      }
      
      .mat-cell {
        padding: 6px 8px;
        font-size: 12px;
      }
      
      .mat-header-cell {
        padding: 8px;
        font-size: 12px;
      }
    }

    /* DN styling for better readability */
    .dn-info {
      font-family: monospace;
      font-size: 11px;
      line-height: 1.4;
      background-color: #f8f9fa;
      padding: 6px 8px;
      border-radius: 3px;
      max-width: 100%;
    }

    .dn-line {
      margin-bottom: 2px;
      word-break: break-word;
      white-space: normal;
    }

    .dn-line:last-child {
      margin-bottom: 0;
    }

    .dn-line strong {
      color: #2c3e50;
      font-weight: bold;
      margin-right: 4px;
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
  `]
})
export class SignedCertificatesComponent implements OnInit {
  private certificatesService = inject(CertificatesService);
  private dialog = inject(MatDialog);
  private dialogService = inject(DialogService);

  certificates: Certificate[] = [];
  certificatesDataSource = new MatTableDataSource<Certificate>();
  loading = false;
  error: string | null = null;

  displayedColumns: string[] = [
    'issuedTo',
    'issuedBy', 
    'status',
    'validFrom',
    'validUntil',
    'certificateType',
    'serialNumber',
    'actions'
  ];

  ngOnInit(): void {
    this.loadCertificates();
    
    // Add cleanup on component destroy
    window.addEventListener('beforeunload', () => {
      this.dialogService.forceCleanup();
    });
  }

  loadCertificates(): void {
    this.loading = true;
    this.error = null;

    this.certificatesService.getCertificatesSignedByMe().subscribe({
      next: (response) => {
        // Handle paginated response
        this.certificates = response.content || response;
        this.certificatesDataSource.data = this.certificates;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load certificates';
        this.loading = false;
        console.error('Error loading certificates:', err);
      }
    });
  }

  openCertificateDetails(certificate: Certificate): void {
    console.log('Opening certificate details dialog for:', certificate);
    
    // Check for existing overlays before opening
    const existingOverlays = document.querySelectorAll('.cdk-overlay-container');
    console.log('Existing overlays before opening:', existingOverlays.length);
    
    // Only clean up if there are existing overlays
    if (existingOverlays.length > 0) {
      console.log('Found existing overlays, cleaning up before opening new dialog');
      this.dialogService.resetOverlayState();
      
      // Wait a bit for cleanup to complete
      setTimeout(() => {
        this.openDialog(certificate);
      }, 100);
    } else {
      // No existing overlays, open dialog directly
      this.openDialog(certificate);
    }
  }

  private openDialog(certificate: Certificate): void {
    console.log('Opening dialog for certificate:', certificate.serialNumber);
    
    const dialogRef = this.dialog.open(CertificateDetailsDialogComponent, {
      width: '900px',
      maxWidth: '90vw',
      maxHeight: '90vh',
      data: { certificate: certificate },
      hasBackdrop: true,
      disableClose: false
    });
    
    dialogRef.afterOpened().subscribe(() => {
      console.log('Certificate details dialog opened successfully');
      
      // Check overlay state after opening
      const overlaysAfterOpen = document.querySelectorAll('.cdk-overlay-container');
      const panesAfterOpen = document.querySelectorAll('.cdk-overlay-pane');
      const backdropsAfterOpen = document.querySelectorAll('.cdk-overlay-backdrop');
      console.log('Overlays after opening:', {
        containers: overlaysAfterOpen.length,
        panes: panesAfterOpen.length,
        backdrops: backdropsAfterOpen.length
      });
    });
    
    dialogRef.afterClosed().subscribe(() => {
      console.log('Certificate details dialog closed');
      
      // Check overlay state after closing
      setTimeout(() => {
        const overlaysAfterClose = document.querySelectorAll('.cdk-overlay-container');
        const panesAfterClose = document.querySelectorAll('.cdk-overlay-pane');
        const backdropsAfterClose = document.querySelectorAll('.cdk-overlay-backdrop');
        console.log('Overlays after closing:', {
          containers: overlaysAfterClose.length,
          panes: panesAfterClose.length,
          backdrops: backdropsAfterClose.length
        });
        
        // Trigger cleanup after dialog closes
        this.dialogService.cleanupOverlays();
      }, 100);
    });
  }

  downloadCertificate(certificate: Certificate): void {
    // CA users can only download PEM format (no private keys)
    const blob = new Blob([certificate.certificateData || ''], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `certificate_${certificate.serialNumber}.pem`;
    link.click();
    window.URL.revokeObjectURL(url);
  }
}
