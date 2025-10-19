import { Component, OnInit, inject } from '@angular/core';
import { CommonModule, DatePipe, NgIf } from '@angular/common';
import { MatTable, MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatHeaderCell, MatHeaderCellDef, MatCell, MatCellDef, MatColumnDef } from '@angular/material/table';
import { MatTableDataSource } from '@angular/material/table';
import { MatIconButton, MatButtonModule } from '@angular/material/button';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ToastrService } from 'ngx-toastr';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { CrlService } from '../../../services/crl/crl.service';
import { DialogService } from '../../../services/dialog/dialog.service';
import { Certificate } from '../../../models/Certificate';
import { DownloadCertificateRequest } from '../../../models/DownloadCertificateRequest';
import { RevokeCertificate } from '../../../models/RevokeCertificate';
import { CertificateDetailsDialogComponent } from '../../common/certificate-details-dialog/certificate-details-dialog.component';
import { RevokeCertificateDialogComponent } from '../../common/revoke-certificate-dialog/revoke-certificate-dialog.component';
import { DownloadCertificatePwDialogComponent } from '../../common/download-certificate-pw-dialog/download-certificate-pw-dialog.component';

@Component({
  selector: 'app-my-certificates',
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
    MatIconButton,
    MatButtonModule,
    MatIconModule,
    MatTooltipModule,
    MatProgressSpinner,
    DatePipe,
    NgIf
  ],
  template: `
    <div class="container">
      <div class="header">
        <h1>My Certificates</h1>
        <p class="subtitle">Manage your personal certificates</p>
      </div>

      <div *ngIf="loading" class="loading">
        <mat-spinner></mat-spinner>
        <p>Loading certificates...</p>
      </div>

      <div *ngIf="!loading && error" class="error">
        <mat-icon>error</mat-icon>
        <p>{{ error }}</p>
        <button mat-raised-button color="primary" (click)="loadCertificates()">Retry</button>
      </div>

      <div *ngIf="!loading && !error" class="table-container">
        <mat-table [dataSource]="certificatesDataSource" class="certificates-table">
          <!-- Issued To Column -->
          <ng-container matColumnDef="issuedTo">
            <mat-header-cell *matHeaderCellDef class="header-cell">Issued To</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              <div class="dn-display">
                <div *ngIf="certificate.subjectCN" class="dn-item">
                  <strong>CN:</strong> {{ certificate.subjectCN }}
                </div>
                <div *ngIf="certificate.subjectO" class="dn-item">
                  <strong>O:</strong> {{ certificate.subjectO }}
                </div>
                <div *ngIf="certificate.subjectOU" class="dn-item">
                  <strong>OU:</strong> {{ certificate.subjectOU }}
                </div>
                <div *ngIf="certificate.subjectE" class="dn-item">
                  <strong>E:</strong> {{ certificate.subjectE }}
                </div>
                <div *ngIf="certificate.subjectC" class="dn-item">
                  <strong>C:</strong> {{ certificate.subjectC }}
                </div>
              </div>
            </mat-cell>
          </ng-container>

          <!-- Issued By Column -->
          <ng-container matColumnDef="issuedBy">
            <mat-header-cell *matHeaderCellDef class="header-cell">Issued By</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              <div class="dn-display">
                <div *ngIf="certificate.issuerCN" class="dn-item">
                  <strong>CN:</strong> {{ certificate.issuerCN }}
                </div>
                <div *ngIf="certificate.issuerO" class="dn-item">
                  <strong>O:</strong> {{ certificate.issuerO }}
                </div>
                <div *ngIf="certificate.issuerOU" class="dn-item">
                  <strong>OU:</strong> {{ certificate.issuerOU }}
                </div>
                <div *ngIf="certificate.issuerE" class="dn-item">
                  <strong>E:</strong> {{ certificate.issuerE }}
                </div>
                <div *ngIf="certificate.issuerC" class="dn-item">
                  <strong>C:</strong> {{ certificate.issuerC }}
                </div>
              </div>
            </mat-cell>
          </ng-container>

          <!-- Status Column -->
          <ng-container matColumnDef="status">
            <mat-header-cell *matHeaderCellDef class="header-cell">Status</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              <span class="status-badge" [ngClass]="'status-' + certificate.status.toLowerCase()">
                {{ certificate.status }}
              </span>
            </mat-cell>
          </ng-container>

          <!-- Valid From Column -->
          <ng-container matColumnDef="validFrom">
            <mat-header-cell *matHeaderCellDef class="header-cell">Valid From</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              {{ certificate.validFrom | date:'medium' }}
            </mat-cell>
          </ng-container>

          <!-- Valid Until Column -->
          <ng-container matColumnDef="validUntil">
            <mat-header-cell *matHeaderCellDef class="header-cell">Valid Until</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              {{ certificate.validTo | date:'medium' }}
            </mat-cell>
          </ng-container>

          <!-- Serial Number Column -->
          <ng-container matColumnDef="serialNumber">
            <mat-header-cell *matHeaderCellDef class="header-cell">Serial Number</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
              <div class="serial-number">
                {{ certificate.serialNumber }}
              </div>
            </mat-cell>
          </ng-container>

          <!-- Actions Column -->
          <ng-container matColumnDef="actions">
            <mat-header-cell *matHeaderCellDef class="header-cell">Actions</mat-header-cell>
            <mat-cell *matCellDef="let certificate" class="cell">
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
                
                <button 
                  *ngIf="certificate.status !== 'REVOKED'" 
                  (click)="openRevokeCertificate(certificate)"
                  class="btn btn-sm btn-danger"
                  title="Revoke Certificate">
                  Revoke
                </button>
              </div>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="displayedColumns" class="header-row"></mat-header-row>
          <mat-row *matRowDef="let row; columns: displayedColumns;" class="data-row"></mat-row>
        </mat-table>

        <div *ngIf="certificates.length === 0" class="no-data">
          <mat-icon>inbox</mat-icon>
          <h3>No Certificates Found</h3>
          <p>You don't have any certificates yet. Request a certificate to get started.</p>
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

    .header {
      margin-bottom: 30px;
      text-align: center;
    }

    .header h1 {
      color: #2c3e50;
      margin: 0 0 10px 0;
      font-size: 2.5rem;
      font-weight: 600;
    }

    .subtitle {
      color: #666;
      margin: 0;
      font-size: 1.1rem;
    }

    .loading {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      color: #666;
    }

    .loading p {
      margin-top: 20px;
      font-size: 1.1rem;
    }

    .error {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      color: #d32f2f;
      text-align: center;
    }

    .error mat-icon {
      font-size: 48px;
      width: 48px;
      height: 48px;
      margin-bottom: 20px;
    }

    .error p {
      margin: 0 0 20px 0;
      font-size: 1.1rem;
    }

    .table-container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      overflow: hidden;
    }

    .certificates-table {
      width: 100%;
      min-width: 1000px;
    }

    .header-cell {
      background: #f8f9fa;
      color: #2c3e50;
      font-weight: 600;
      font-size: 14px;
      padding: 16px 12px;
      border-bottom: 2px solid #e0e0e0;
    }

    .cell {
      padding: 16px 12px;
      border-bottom: 1px solid #f0f0f0;
      vertical-align: top;
    }

    .data-row:hover {
      background: #f8f9fa;
    }

    .dn-display {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .dn-item {
      font-size: 13px;
      line-height: 1.4;
    }

    .dn-item strong {
      color: #2c3e50;
      font-weight: 600;
    }

    .status-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .status-active {
      background: #e8f5e8;
      color: #2e7d32;
    }

    .status-revoked {
      background: #ffebee;
      color: #c62828;
    }

    .status-expired {
      background: #fff3e0;
      color: #ef6c00;
    }

    .serial-number {
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: #666;
      word-break: break-all;
      line-height: 1.3;
    }

    .action-buttons {
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
    }

    .no-data {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      color: #666;
      text-align: center;
    }

    .no-data mat-icon {
      font-size: 64px;
      width: 64px;
      height: 64px;
      margin-bottom: 20px;
      color: #ccc;
    }

    .no-data h3 {
      margin: 0 0 10px 0;
      color: #2c3e50;
      font-size: 1.5rem;
    }

    .no-data p {
      margin: 0;
      font-size: 1.1rem;
    }

    @media (max-width: 768px) {
      .container {
        padding: 10px;
      }

      .header h1 {
        font-size: 2rem;
      }

      .certificates-table {
        min-width: 800px;
      }
    }
  `]
})
export class MyCertificatesComponent implements OnInit {
  private certificatesService = inject(CertificatesService);
  private crlService = inject(CrlService);
  private dialog = inject(MatDialog);
  private dialogService = inject(DialogService);
  private toastr = inject(ToastrService);

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
    'serialNumber',
    'actions'
  ];

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.error = null;

    this.certificatesService.getMyCertificates().subscribe({
      next: (certificates) => {
        this.certificates = certificates;
        this.certificatesDataSource.data = this.certificates;
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading certificates:', err);
        this.error = 'Failed to load certificates. Please try again.';
        this.loading = false;
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

  openRevokeCertificate(certificate: Certificate): void {
    const dialogRef = this.dialog.open(RevokeCertificateDialogComponent, {
      width: '600px',
      maxWidth: '90vw',
      maxHeight: '90vh',
      data: { certificate: certificate },
      hasBackdrop: true,
      disableClose: false
    });

    dialogRef.afterClosed().subscribe(result => {
      // Trigger cleanup after dialog closes
      setTimeout(() => this.dialogService.cleanupOverlays(), 100);
      
      if (result) {
        const revokeRequest: RevokeCertificate = {
          serialNumber: certificate.serialNumber,
          revocationReason: result.revocationReason
        };

        this.crlService.revokeCertificate(revokeRequest).subscribe({
          next: () => {
            this.toastr.success('Certificate revoked successfully');
            this.loadCertificates(); // Refresh the list
          },
          error: (err) => {
            console.error('Error revoking certificate:', err);
            this.toastr.error('Failed to revoke certificate');
          }
        });
      }
    });
  }

  downloadCertificate(certificate: Certificate): void {
    const dialogRef = this.dialog.open(DownloadCertificatePwDialogComponent, {
      width: '600px',
      maxWidth: '90vw',
      maxHeight: '90vh',
      data: { certificate: certificate },
      hasBackdrop: true,
      disableClose: false
    });

    dialogRef.afterClosed().subscribe(password => {
      // Trigger cleanup after dialog closes
      setTimeout(() => this.dialogService.cleanupOverlays(), 100);
      
      if (password) {
        const downloadRequest: DownloadCertificateRequest = {
          certificateSerialNumber: certificate.serialNumber,
          password: password
        };

        this.certificatesService.downloadCertificate(downloadRequest).subscribe({
          next: (blob) => {
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `certificate_${certificate.serialNumber}.pfx`;
            link.click();
            window.URL.revokeObjectURL(url);
            this.toastr.success('Certificate downloaded successfully');
          },
          error: (err) => {
            console.error('Error downloading certificate:', err);
            this.toastr.error('Failed to download certificate');
          }
        });
      }
    });
  }
}
