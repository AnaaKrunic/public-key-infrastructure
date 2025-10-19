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
            
            <!-- Subject Alternative Names -->
            <div class="extension-group">
              <label class="extension-label">Subject Alternative Names</label>
              <div class="chip-container">
                <span class="chip" *ngFor="let san of subjectAlternativeNames">
                  {{ san }}
                  <button type="button" class="chip-remove" (click)="removeSan(san)">×</button>
                </span>
              </div>
              <div class="input-with-button">
                <mat-form-field appearance="outline" class="flex-field">
                  <mat-label>Add SAN</mat-label>
                  <input matInput [(ngModel)]="newSan" placeholder="e.g., example.com" (keyup.enter)="addSan()">
                </mat-form-field>
                <button mat-icon-button color="primary" (click)="addSan()" type="button">
                  <mat-icon>add</mat-icon>
                </button>
              </div>
            </div>
            
            <!-- Issuer Alternative Names -->
            <div class="extension-group">
              <label class="extension-label">Issuer Alternative Names</label>
              <div class="chip-container">
                <span class="chip" *ngFor="let ian of issuerAlternativeNames">
                  {{ ian }}
                  <button type="button" class="chip-remove" (click)="removeIan(ian)">×</button>
                </span>
              </div>
              <div class="input-with-button">
                <mat-form-field appearance="outline" class="flex-field">
                  <mat-label>Add IAN</mat-label>
                  <input matInput [(ngModel)]="newIan" placeholder="e.g., issuer.example.com" (keyup.enter)="addIan()">
                </mat-form-field>
                <button mat-icon-button color="primary" (click)="addIan()" type="button">
                  <mat-icon>add</mat-icon>
                </button>
              </div>
            </div>
            
            <!-- Name Constraints -->
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Name Constraints</mat-label>
              <input matInput [(ngModel)]="nameConstraints" placeholder="e.g., .example.com">
              <mat-hint>Specify permitted/excluded subtrees</mat-hint>
            </mat-form-field>
            
            <!-- Basic Constraints -->
            <div class="extension-group">
              <label class="extension-label">Basic Constraints</label>
              <div class="constraint-row">
                <mat-form-field appearance="outline" class="half-width">
                  <mat-label>Is CA</mat-label>
                  <mat-select [(ngModel)]="basicConstraints.isCa">
                    <mat-option [value]="true">Yes</mat-option>
                    <mat-option [value]="false">No</mat-option>
                  </mat-select>
                </mat-form-field>
                <mat-form-field appearance="outline" class="half-width">
                  <mat-label>Path Length</mat-label>
                  <input matInput type="number" [(ngModel)]="basicConstraints.pathLen" placeholder="Path length constraint" min="0">
                </mat-form-field>
              </div>
            </div>
            
            <!-- Certificate Policy -->
            <div class="extension-group">
              <label class="extension-label">Certificate Policy</label>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Policy Identifier (OID)</mat-label>
                <input matInput [(ngModel)]="certificatePolicy.policyIdentifier" placeholder="e.g., 2.5.29.32.0">
              </mat-form-field>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>CPS URI (Optional)</mat-label>
                <input matInput [(ngModel)]="certificatePolicy.cpsUri" placeholder="https://example.com/cps">
              </mat-form-field>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>User Notice (Optional)</mat-label>
                <input matInput [(ngModel)]="certificatePolicy.userNotice" placeholder="User notice text">
              </mat-form-field>
            </div>
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
    
    /* Extension groups */
    .extension-group {
      margin-bottom: 24px;
      padding: 16px;
      background: #f8f9fa;
      border-radius: 8px;
      border: 1px solid #e9ecef;
    }
    
    .extension-label {
      display: block;
      font-weight: 700;
      color: #495057;
      font-size: 14px;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .chip-container {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
      min-height: 40px;
      padding: 8px;
      background: white;
      border-radius: 6px;
      border: 1px solid #dee2e6;
    }
    
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      background: #e9ecef;
      border-radius: 16px;
      font-size: 13px;
      color: #495057;
      font-weight: 500;
      border: 1px solid #ced4da;
    }
    
    .chip-remove {
      background: none;
      border: none;
      color: #dc3545;
      cursor: pointer;
      font-size: 18px;
      font-weight: bold;
      padding: 0;
      line-height: 1;
      margin-left: 4px;
    }
    
    .chip-remove:hover {
      color: #c82333;
      transform: scale(1.2);
    }
    
    .input-with-button {
      display: flex;
      gap: 8px;
      align-items: flex-start;
    }
    
    .flex-field {
      flex: 1;
    }
    
    .constraint-row {
      display: flex;
      gap: 16px;
    }
    
    .half-width {
      flex: 1;
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
      
      .constraint-row {
        flex-direction: column;
        gap: 0;
      }
      
      .input-with-button {
        flex-direction: column;
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
  
  // Additional extension fields
  subjectAlternativeNames: string[] = [];
  issuerAlternativeNames: string[] = [];
  nameConstraints: string = '';
  basicConstraints = { isCa: false, pathLen: null as number | null };
  certificatePolicy = { policyIdentifier: '', cpsUri: '', userNotice: '' };
  
  // For adding SANs/IANs
  newSan: string = '';
  newIan: string = '';

  constructor(@Inject(MAT_DIALOG_DATA) public data: CertificateRequest) {
    this.request = data;
  }

  onCancel(): void {
    this.dialogRef.close();
  }

  onApprove(): void {
    if (this.isFormValid()) {
      // Prepare extension data (requestId and validityDays are passed as separate params)
      const extensionData = {
        keyUsage: this.keyUsage,
        extendedKeyUsage: this.extendedKeyUsage,
        subjectAlternativeNames: this.subjectAlternativeNames,
        issuerAlternativeNames: this.issuerAlternativeNames,
        nameConstraints: this.nameConstraints,
        basicConstraints: JSON.stringify(this.basicConstraints),
        certificatePolicy: JSON.stringify(this.certificatePolicy)
      };
      
      this.certificateRequestsService.approveCertificateRequest(
        this.request.id,
        this.validityDays,
        extensionData
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
  
  // Extension management methods
  addSan(): void {
    if (this.newSan && !this.subjectAlternativeNames.includes(this.newSan.trim())) {
      this.subjectAlternativeNames.push(this.newSan.trim());
      this.newSan = '';
    }
  }
  
  removeSan(san: string): void {
    const index = this.subjectAlternativeNames.indexOf(san);
    if (index > -1) {
      this.subjectAlternativeNames.splice(index, 1);
    }
  }
  
  addIan(): void {
    if (this.newIan && !this.issuerAlternativeNames.includes(this.newIan.trim())) {
      this.issuerAlternativeNames.push(this.newIan.trim());
      this.newIan = '';
    }
  }
  
  removeIan(ian: string): void {
    const index = this.issuerAlternativeNames.indexOf(ian);
    if (index > -1) {
      this.issuerAlternativeNames.splice(index, 1);
    }
  }
}
