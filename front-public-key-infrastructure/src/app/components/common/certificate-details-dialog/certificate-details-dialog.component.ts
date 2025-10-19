import { Component, Inject, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogRef, MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-certificate-details-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule],
  template: `
    <div class="dialog-container">
      <h2 mat-dialog-title>Certificate Details</h2>
      
      <div mat-dialog-content class="certificate-details">
        <div *ngIf="certificateData" class="details-grid">
          <div class="detail-item">
            <label>Serial Number:</label>
            <span class="serial-number">{{ certificateData.serialNumber }}</span>
          </div>
          
          <div class="detail-item">
            <label>Subject DN:</label>
            <span>{{ certificateData.subjectDN }}</span>
          </div>
          
          <div class="detail-item">
            <label>Issuer DN:</label>
            <span>{{ certificateData.issuerDN }}</span>
          </div>
          
          <div class="detail-item">
            <label>Valid From:</label>
            <span>{{ certificateData.validFrom | date:'medium' }}</span>
          </div>
          
          <div class="detail-item">
            <label>Valid To:</label>
            <span>{{ certificateData.validTo | date:'medium' }}</span>
          </div>
          
          <div class="detail-item">
            <label>Status:</label>
            <span [class]="'status-' + certificateData.status.toLowerCase()">
              {{ certificateData.status }}
            </span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.subjectCN">
            <label>Common Name:</label>
            <span>{{ certificateData.subjectCN }}</span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.subjectO">
            <label>Organization:</label>
            <span>{{ certificateData.subjectO }}</span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.subjectOU">
            <label>Organizational Unit:</label>
            <span>{{ certificateData.subjectOU }}</span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.subjectE">
            <label>Email:</label>
            <span>{{ certificateData.subjectE }}</span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.keyUsage">
            <label>Key Usage:</label>
            <span>{{ certificateData.keyUsage }}</span>
          </div>
          
          <div class="detail-item" *ngIf="certificateData.extendedKeyUsage">
            <label>Extended Key Usage:</label>
            <span>{{ certificateData.extendedKeyUsage }}</span>
          </div>
        </div>
        
        <div *ngIf="!certificateData" class="no-data">
          No certificate data available.
        </div>
      </div>
      
      <div mat-dialog-actions class="dialog-actions">
        <button mat-button (click)="onClose()">Close</button>
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
      border-bottom: 2px solid #e0e0e0;
      color: #2c3e50;
      font-size: 24px;
      font-weight: 600;
    }
    
    .certificate-details {
      max-height: 65vh;
      overflow-y: auto;
      padding: 8px 0;
    }
    
    .details-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
    }
    
    .detail-item {
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 16px;
      background: #f8f9fa;
      border-radius: 8px;
      border-left: 4px solid #007bff;
      transition: all 0.2s ease;
    }
    
    .detail-item:hover {
      background: #e9ecef;
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .detail-item label {
      font-weight: 700;
      color: #495057;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    
    .detail-item span {
      font-size: 15px;
      word-break: break-word;
      color: #212529;
      line-height: 1.4;
    }
    
    .serial-number {
      font-family: 'Courier New', monospace;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-align: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .status-active {
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
    
    .status-expired {
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
    
    .status-revoked {
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
    
    .no-data {
      text-align: center;
      padding: 60px 20px;
      color: #6c757d;
      font-size: 16px;
      background: #f8f9fa;
      border-radius: 8px;
      border: 2px dashed #dee2e6;
    }
    
    .dialog-actions {
      justify-content: flex-end;
      padding: 24px 0 0 0;
      border-top: 1px solid #e0e0e0;
      margin-top: 16px;
    }
    
    .dialog-actions button {
      min-width: 100px;
      padding: 10px 24px;
      font-weight: 600;
      border-radius: 6px;
      transition: all 0.2s ease;
    }
    
    .dialog-actions button:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
      .dialog-container {
        min-width: 90vw;
        max-width: 95vw;
      }
      
      .details-grid {
        grid-template-columns: 1fr;
        gap: 12px;
      }
      
      .detail-item {
        padding: 12px;
      }
    }
  `]
})
export class CertificateDetailsDialogComponent {
  private dialogRef = inject(MatDialogRef<CertificateDetailsDialogComponent>);
  
  certificateData: any = null;

  constructor(@Inject(MAT_DIALOG_DATA) public data: any) {
    this.certificateData = data?.encodedCertificate || data?.certificate || null;
  }

  onClose(): void {
    this.dialogRef.close();
  }
}
