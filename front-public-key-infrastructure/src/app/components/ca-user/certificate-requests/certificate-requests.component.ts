import { Component, OnInit, inject } from '@angular/core';
import { CommonModule, DatePipe, NgIf } from '@angular/common';
import { MatTable, MatTableDataSource, MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatHeaderCell, MatHeaderCellDef, MatCell, MatCellDef, MatColumnDef } from '@angular/material/table';
import { MatIconButton } from '@angular/material/button';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { CertificateRequestsService } from '../../../services/certificates/certificate-requests.service';
import { DialogService } from '../../../services/dialog/dialog.service';
import { CertificateRequest } from '../../../models/CertificateRequest';
import { EditCertificateRequestDialogComponent } from './edit-certificate-request-dialog/edit-certificate-request-dialog.component';

@Component({
  selector: 'app-certificate-requests',
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
    MatProgressSpinner,
    NgIf,
    DatePipe
  ],
  template: `
    <div class="container">
      <h1>Pending Certificate Requests</h1>
      
      <div *ngIf="loading" class="loading">
        <mat-spinner></mat-spinner>
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="!loading && !error" class="table-container">
        <mat-table [dataSource]="requestsDataSource" class="requests-table">
          <ng-container matColumnDef="subject">
            <mat-header-cell *matHeaderCellDef>Subject (CN)</mat-header-cell>
            <mat-cell *matCellDef="let request">
              {{ request.subjectCN || request.commonName }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="organization">
            <mat-header-cell *matHeaderCellDef>Organization</mat-header-cell>
            <mat-cell *matCellDef="let request">
              {{ request.subjectO || request.organization }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="organizationalUnit">
            <mat-header-cell *matHeaderCellDef>Organization unit</mat-header-cell>
            <mat-cell *matCellDef="let request">
              {{ request.subjectOU || request.organizationalUnit }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="submittedOn">
            <mat-header-cell *matHeaderCellDef>Submitted on</mat-header-cell>
            <mat-cell *matCellDef="let request">
              {{ (request.createdAt || request.submittedOn) | date:'HH:mm:ss dd.MM.yyyy.' }}
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="status">
            <mat-header-cell *matHeaderCellDef>Status</mat-header-cell>
            <mat-cell *matCellDef="let request">
              <span [class]="'status-' + (request.status || 'PENDING').toLowerCase()">
                {{ request.status || 'PENDING' }}
              </span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="actions">
            <mat-header-cell *matHeaderCellDef>Actions</mat-header-cell>
            <mat-cell *matCellDef="let request">
              <div class="action-buttons">
                <button 
                  *ngIf="request.status === 'PENDING'"
                  (click)="approveRequest(request)" 
                  class="btn btn-sm btn-success"
                  title="Approve Request">
                  Approve
                </button>
                <button 
                  *ngIf="request.status === 'PENDING'"
                  (click)="rejectRequest(request)" 
                  class="btn btn-sm btn-danger"
                  title="Reject Request">
                  Reject
                </button>
                <button 
                  (click)="openEditCertificate(request)" 
                  class="btn btn-sm btn-secondary"
                  title="View/Edit Request">
                  Details
                </button>
              </div>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="displayedColumns"></mat-header-row>
          <mat-row *matRowDef="let row; columns: displayedColumns;"></mat-row>
        </mat-table>

        <div *ngIf="requests.length === 0" class="no-data">
          No pending certificate requests found.
        </div>
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 1200px;
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
    }

    .requests-table {
      width: 100%;
    }

    .status-pending {
      color: #ffc107;
      font-weight: bold;
    }

    .status-approved {
      color: #28a745;
      font-weight: bold;
    }

    .status-rejected {
      color: #dc3545;
      font-weight: bold;
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

    .btn-success {
      background-color: #28a745;
      color: white;
    }

    .btn-success:hover {
      background-color: #218838;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-danger:hover {
      background-color: #c82333;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-secondary:hover {
      background-color: #5a6268;
    }
  `]
})
export class CertificateRequestsComponent implements OnInit {
  private certificateRequestsService = inject(CertificateRequestsService);
  private dialog = inject(MatDialog);
  private dialogService = inject(DialogService);

  requests: CertificateRequest[] = [];
  requestsDataSource = new MatTableDataSource<CertificateRequest>();
  loading = false;
  error: string | null = null;

  displayedColumns: string[] = [
    'subject',
    'organization',
    'organizationalUnit',
    'submittedOn',
    'status',
    'actions'
  ];

  ngOnInit(): void {
    this.loadRequests();
  }

  loadRequests(): void {
    this.loading = true;
    this.error = null;

    this.certificateRequestsService.getPendingCertificateRequests().subscribe({
      next: (response) => {
        // Handle paginated response
        this.requests = response.content || response;
        this.requestsDataSource.data = this.requests;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load certificate requests';
        this.loading = false;
        console.error('Error loading certificate requests:', err);
      }
    });
  }

  approveRequest(request: CertificateRequest): void {
    const commonName = request.subjectCN || request.commonName;
    if (confirm(`Are you sure you want to approve certificate request for ${commonName}?`)) {
      this.certificateRequestsService.approveCertificateRequest(request.id, 365).subscribe({
        next: () => {
          this.loadRequests(); // Reload the list
        },
        error: (err) => {
          console.error('Error approving certificate request:', err);
          alert('Failed to approve certificate request');
        }
      });
    }
  }

  rejectRequest(request: CertificateRequest): void {
    const commonName = request.subjectCN || request.commonName;
    if (confirm(`Are you sure you want to reject certificate request for ${commonName}?`)) {
      this.certificateRequestsService.rejectCertificateRequest(request.id).subscribe({
        next: () => {
          this.loadRequests(); // Reload the list
        },
        error: (err) => {
          console.error('Error rejecting certificate request:', err);
          alert('Failed to reject certificate request');
        }
      });
    }
  }

  openEditCertificate(request: CertificateRequest): void {
    const dialogRef = this.dialog.open(EditCertificateRequestDialogComponent, {
      width: '900px',
      maxWidth: '90vw',
      maxHeight: '90vh',
      data: request,
      hasBackdrop: true,
      disableClose: false
    });

    dialogRef.afterClosed().subscribe(result => {
      // Trigger cleanup after dialog closes
      setTimeout(() => this.dialogService.cleanupOverlays(), 100);
      
      if (result === 'reload') {
        this.loadRequests();
      }
    });
  }
}
