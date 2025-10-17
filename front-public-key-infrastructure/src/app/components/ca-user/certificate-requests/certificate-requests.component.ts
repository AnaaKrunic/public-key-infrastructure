import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CertificateRequestsService } from '../../../services/certificates/certificate-requests.service';
import { CertificateRequest } from '../../../models/CertificateRequest';

@Component({
  selector: 'app-certificate-requests',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>Pending Certificate Requests</h1>
      
      <div *ngIf="loading" class="loading">
        Loading certificate requests...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="requests.length > 0" class="requests-table">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Common Name</th>
              <th>Organization</th>
              <th>Email</th>
              <th>Submitted On</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let request of requests">
              <td>{{ request.id }}</td>
              <td>{{ request.commonName }}</td>
              <td>{{ request.organization }}</td>
              <td>{{ request.email }}</td>
              <td>{{ formatDate(request.submittedOn) }}</td>
              <td>
                <span [class]="'status-' + (request.status || 'pending').toLowerCase()">
                  {{ request.status || 'PENDING' }}
                </span>
              </td>
              <td>
                <button (click)="approveRequest(request)" class="btn btn-sm btn-success">
                  Approve
                </button>
                <button (click)="rejectRequest(request)" class="btn btn-sm btn-danger">
                  Reject
                </button>
                <button (click)="viewDetails(request)" class="btn btn-sm btn-secondary">
                  Details
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && requests.length === 0" class="no-data">
        No pending certificate requests found.
      </div>

      <!-- Approval Modal -->
      <div *ngIf="showApprovalModal" class="modal-overlay" (click)="closeApprovalModal()">
        <div class="modal" (click)="$event.stopPropagation()">
          <h3>Approve Certificate Request</h3>
          <form (ngSubmit)="confirmApproval()" #approvalForm="ngForm">
            <div class="form-group">
              <label for="validityDays">Validity Days *</label>
              <input 
                type="number" 
                id="validityDays" 
                name="validityDays" 
                [(ngModel)]="approvalData.validityDays" 
                required
                min="1"
                max="365"
                class="form-control">
            </div>
            <div class="form-actions">
              <button type="submit" [disabled]="!approvalForm.form.valid" class="btn btn-primary">
                Approve
              </button>
              <button type="button" (click)="closeApprovalModal()" class="btn btn-secondary">
                Cancel
              </button>
            </div>
          </form>
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

    .loading, .error, .no-data {
      text-align: center;
      padding: 20px;
      font-size: 16px;
    }

    .error {
      color: #dc3545;
    }

    .requests-table {
      margin-top: 20px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
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

    .btn {
      padding: 6px 12px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      margin-right: 5px;
    }

    .btn-sm {
      padding: 4px 8px;
      font-size: 11px;
    }

    .btn-success {
      background-color: #28a745;
      color: white;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-primary {
      background-color: #007bff;
      color: white;
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
    }

    .form-group {
      margin-bottom: 15px;
    }

    label {
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

    .form-actions {
      margin-top: 20px;
      display: flex;
      gap: 10px;
    }
  `]
})
export class CertificateRequestsComponent implements OnInit {
  requests: CertificateRequest[] = [];
  loading = false;
  error: string | null = null;
  showApprovalModal = false;
  selectedRequest: CertificateRequest | null = null;
  approvalData = { validityDays: 30 };

  constructor(private certificateRequestsService: CertificateRequestsService) {}

  ngOnInit(): void {
    this.loadRequests();
  }

  loadRequests(): void {
    this.loading = true;
    this.error = null;

    this.certificateRequestsService.getPendingCertificateRequests().subscribe({
      next: (reqs) => {
        this.requests = reqs;
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
    this.selectedRequest = request;
    this.approvalData.validityDays = 30;
    this.showApprovalModal = true;
  }

  confirmApproval(): void {
    if (!this.selectedRequest) return;

    this.certificateRequestsService.approveCertificateRequest(
      this.selectedRequest.id,
      this.approvalData.validityDays
    ).subscribe({
      next: () => {
        this.closeApprovalModal();
        this.loadRequests(); // Refresh the list
      },
      error: (err) => {
        console.error('Error approving certificate request:', err);
        alert('Failed to approve certificate request');
      }
    });
  }

  rejectRequest(request: CertificateRequest): void {
    if (confirm(`Are you sure you want to reject certificate request ${request.id}?`)) {
      this.certificateRequestsService.rejectCertificateRequest(request.id).subscribe({
        next: () => {
          this.loadRequests(); // Refresh the list
        },
        error: (err) => {
          console.error('Error rejecting certificate request:', err);
          alert('Failed to reject certificate request');
        }
      });
    }
  }

  viewDetails(request: CertificateRequest): void {
    // TODO: Implement certificate request details modal
    console.log('View details for request:', request);
  }

  closeApprovalModal(): void {
    this.showApprovalModal = false;
    this.selectedRequest = null;
    this.approvalData.validityDays = 30;
  }

  formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString();
  }
}
