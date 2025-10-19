import { Component, Inject, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { CertificateRequest } from '../../../../models/CertificateRequest';
import { CertificateRequestsService } from '../../../../services/certificates/certificate-requests.service';

@Component({
  selector: 'app-edit-certificate-request-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatIconModule
  ],
  template: `
    <div class="dialog-container">
      <h2 mat-dialog-title>Certificate Request Details</h2>
      
      <div mat-dialog-content class="request-content">
        <div class="request-info">
          <div class="info-section">
            <h3>Request Information</h3>
            <div class="info-grid">
              <div class="info-item">
                <label>Request ID:</label>
                <span>{{ request.id }}</span>
              </div>
              <div class="info-item">
                <label>Common Name:</label>
                <span>{{ request.commonName }}</span>
              </div>
              <div class="info-item">
                <label>Organization:</label>
                <span>{{ request.organization }}</span>
              </div>
              <div class="info-item">
                <label>Organizational Unit:</label>
                <span>{{ request.organizationalUnit }}</span>
              </div>
              <div class="info-item">
                <label>Email:</label>
                <span>{{ request.email }}</span>
              </div>
              <div class="info-item">
                <label>Submitted On:</label>
                <span>{{ request.submittedOn | date:'medium' }}</span>
              </div>
              <div class="info-item">
                <label>Status:</label>
                <span [class]="'status-' + (request.status || 'pending').toLowerCase()">
                  {{ request.status || 'PENDING' }}
                </span>
              </div>
            </div>
          </div>
          
          <div class="action-section" *ngIf="request.status === 'PENDING'">
            <h3>Certificate Details</h3>
            
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Validity Days</mat-label>
              <input 
                matInput 
                type="number"
                [(ngModel)]="validityDays" 
                placeholder="Enter validity in days"
                required
                min="1"
                max="365">
              <mat-hint>Certificate will be valid for this many days</mat-hint>
            </mat-form-field>
            
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Key Usage</mat-label>
              <mat-select [(ngModel)]="keyUsage" multiple>
                <mat-option value="DIGITAL_SIGNATURE">Digital Signature</mat-option>
                <mat-option value="NON_REPUDIATION">Non Repudiation</mat-option>
                <mat-option value="KEY_ENCIPHERMENT">Key Encipherment</mat-option>
                <mat-option value="DATA_ENCIPHERMENT">Data Encipherment</mat-option>
                <mat-option value="KEY_AGREEMENT">Key Agreement</mat-option>
                <mat-option value="KEY_CERT_SIGN">Key Cert Sign</mat-option>
                <mat-option value="CRL_SIGN">CRL Sign</mat-option>
                <mat-option value="ENCIPHER_ONLY">Encipher Only</mat-option>
                <mat-option value="DECIPHER_ONLY">Decipher Only</mat-option>
              </mat-select>
            </mat-form-field>
            
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Extended Key Usage</mat-label>
              <mat-select [(ngModel)]="extendedKeyUsage" multiple>
                <mat-option value="SERVER_AUTH">Server Authentication</mat-option>
                <mat-option value="CLIENT_AUTH">Client Authentication</mat-option>
                <mat-option value="CODE_SIGNING">Code Signing</mat-option>
                <mat-option value="EMAIL_PROTECTION">Email Protection</mat-option>
                <mat-option value="TIME_STAMPING">Time Stamping</mat-option>
                <mat-option value="OCSP_SIGNING">OCSP Signing</mat-option>
              </mat-select>
            </mat-form-field>
          </div>
        </div>
      </div>
      
      <div mat-dialog-actions class="dialog-actions">
        <button mat-button (click)="onCancel()">Cancel</button>
        <button 
          mat-button 
          (click)="onReject()" 
          *ngIf="request.status === 'PENDING'"
          color="warn">
          Reject
        </button>
        <button 
          mat-raised-button 
          color="primary" 
          (click)="onApprove()"
          *ngIf="request.status === 'PENDING'"
          [disabled]="!isFormValid()">
          Approve
        </button>
      </div>
    </div>
  `,
  styles: [`
    .dialog-container {
      min-width: 700px;
      max-width: 900px;
      max-height: 90vh;
      margin: 0;
      padding: 0;
    }
    
    h2[mat-dialog-title] {
      margin: 0 0 24px 0;
      padding: 0 0 16px 0;
      border-bottom: 2px solid #17a2b8;
      color: #17a2b8;
      font-size: 24px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    
    h2[mat-dialog-title]::before {
      content: "📋";
      font-size: 20px;
    }
    
    .request-content {
      max-height: 65vh;
      overflow-y: auto;
      padding: 8px 0;
    }
    
    .request-info {
      display: flex;
      flex-direction: column;
      gap: 32px;
    }
    
    .info-section {
      background: #f8f9fa;
      padding: 24px;
      border-radius: 12px;
      border: 1px solid #e9ecef;
    }
    
    .action-section {
      background: #fff;
      padding: 24px;
      border-radius: 12px;
      border: 2px solid #e9ecef;
      box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    
    .info-section h3,
    .action-section h3 {
      margin: 0 0 20px 0;
      color: #2c3e50;
      font-size: 20px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .info-section h3::before {
      content: "ℹ️";
      font-size: 16px;
    }
    
    .action-section h3::before {
      content: "⚙️";
      font-size: 16px;
    }
    
    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
    }
    
    .info-item {
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 16px;
      background: white;
      border-radius: 8px;
      border: 1px solid #e9ecef;
      transition: all 0.2s ease;
    }
    
    .info-item:hover {
      background: #f8f9fa;
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .info-item label {
      font-weight: 700;
      color: #495057;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    
    .info-item span {
      font-size: 15px;
      word-break: break-word;
      color: #212529;
      line-height: 1.4;
    }
    
    .status-pending {
      color: #ffc107;
      font-weight: 700;
      background: #fff3cd;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      display: inline-block;
      border: 1px solid #ffeaa7;
    }
    
    .status-approved {
      color: #28a745;
      font-weight: 700;
      background: #d4edda;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      display: inline-block;
      border: 1px solid #c3e6cb;
    }
    
    .status-rejected {
      color: #dc3545;
      font-weight: 700;
      background: #f8d7da;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      display: inline-block;
      border: 1px solid #f5c6cb;
    }
    
    .full-width {
      width: 100%;
      margin-bottom: 20px;
    }
    
    .full-width mat-form-field {
      width: 100%;
    }
    
    .full-width mat-form-field .mat-mdc-form-field-subscript-wrapper {
      margin-top: 8px;
    }
    
    .full-width mat-form-field .mat-mdc-form-field-hint {
      color: #6c757d;
      font-size: 12px;
    }
    
    .full-width input[matInput] {
      font-weight: 500;
    }
    
    .full-width .mat-mdc-select-value {
      color: #495057;
      font-weight: 500;
    }
    
    .full-width .mat-mdc-select-arrow {
      color: #6c757d;
    }
    
    .dialog-actions {
      justify-content: flex-end;
      gap: 12px;
      padding: 24px 0 0 0;
      border-top: 1px solid #e0e0e0;
      margin-top: 16px;
    }
    
    .dialog-actions button {
      min-width: 120px;
      padding: 12px 24px;
      font-weight: 600;
      border-radius: 6px;
      transition: all 0.2s ease;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .dialog-actions button[mat-button] {
      color: #6c757d;
      border: 1px solid #dee2e6;
    }
    
    .dialog-actions button[mat-button]:hover {
      background: #f8f9fa;
      border-color: #adb5bd;
      transform: translateY(-1px);
    }
    
    .dialog-actions button[mat-button][color="warn"] {
      color: #dc3545;
      border-color: #dc3545;
    }
    
    .dialog-actions button[mat-button][color="warn"]:hover {
      background: #f8d7da;
      border-color: #c82333;
    }
    
    .dialog-actions button[mat-raised-button] {
      background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(23, 162, 184, 0.3);
    }
    
    .dialog-actions button[mat-raised-button]:hover:not(:disabled) {
      background: linear-gradient(135deg, #138496 0%, #117a8b 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 16px rgba(23, 162, 184, 0.4);
    }
    
    .dialog-actions button[mat-raised-button]:disabled {
      background: #6c757d;
      color: #adb5bd;
      box-shadow: none;
      cursor: not-allowed;
    }
    
    /* Form field focus states */
    .full-width mat-form-field.mat-focused .mat-mdc-form-field-focus-overlay {
      background-color: rgba(23, 162, 184, 0.04);
    }
    
    .full-width mat-form-field.mat-focused .mat-mdc-form-field-outline-thick {
      color: #17a2b8;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
      .dialog-container {
        min-width: 90vw;
        max-width: 95vw;
      }
      
      .info-grid {
        grid-template-columns: 1fr;
        gap: 12px;
      }
      
      .info-item {
        padding: 12px;
      }
      
      .dialog-actions {
        flex-direction: column;
        gap: 8px;
      }
      
      .dialog-actions button {
        width: 100%;
        min-width: auto;
      }
    }
  `]
})
export class EditCertificateRequestDialogComponent {
  private dialogRef = inject(MatDialogRef<EditCertificateRequestDialogComponent>);
  private certificateRequestsService = inject(CertificateRequestsService);
  
  request: CertificateRequest;
  validityDays: number = 30;
  keyUsage: string[] = ['DIGITAL_SIGNATURE', 'KEY_ENCIPHERMENT'];
  extendedKeyUsage: string[] = ['SERVER_AUTH'];

  constructor(@Inject(MAT_DIALOG_DATA) public data: CertificateRequest) {
    this.request = data;
  }

  onCancel(): void {
    this.dialogRef.close();
  }

  onApprove(): void {
    if (this.isFormValid()) {
      this.certificateRequestsService.approveCertificateRequest(
        this.request.id,
        this.validityDays
      ).subscribe({
        next: () => {
          this.dialogRef.close('reload');
        },
        error: (err) => {
          console.error('Error approving certificate request:', err);
          alert('Failed to approve certificate request');
        }
      });
    }
  }

  onReject(): void {
    if (confirm(`Are you sure you want to reject certificate request ${this.request.id}?`)) {
      this.certificateRequestsService.rejectCertificateRequest(this.request.id).subscribe({
        next: () => {
          this.dialogRef.close('reload');
        },
        error: (err) => {
          console.error('Error rejecting certificate request:', err);
          alert('Failed to reject certificate request');
        }
      });
    }
  }

  isFormValid(): boolean {
    return this.validityDays > 0 && this.validityDays <= 365;
  }
}
