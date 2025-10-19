import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth/auth.service';
import { MfaService } from '../services/mfa.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  userEmail: string = '';
  mfaEnabled: boolean = false;
  showMfaSetup: boolean = false;
  isLoadingMfa: boolean = false;
  isLoadingVerification: boolean = false;
  qrCodeImage: string = '';
  secretKey: string = '';
  verificationCode: string = '';
  verificationError: string = '';

  constructor(
    private authService: AuthService,
    private router: Router,
    private mfaService: MfaService
  ) {}

  ngOnInit() {
    // Check if user is logged in
    const accessToken = this.authService.accessToken;
    if (!accessToken) {
      this.router.navigate(['/login']);
      return;
    }

    // Get user email from JWT token
    this.userEmail = this.authService.userEmail || 'Unknown';
    
    if (!this.userEmail || this.userEmail === 'Unknown') {
      console.error('Could not extract email from JWT token');
      this.userEmail = 'Unknown';
      return;
    }
    
    // Check MFA status from backend
    this.mfaService.getMfaStatus(this.userEmail).subscribe({
      next: (response: {mfaEnabled: boolean}) => {
        this.mfaEnabled = response.mfaEnabled;
      },
      error: (error: any) => {
        console.error('Error getting MFA status:', error);
        this.mfaEnabled = false;
      }
    });
  }

  enableMfa() {
    this.isLoadingMfa = true;
    this.mfaService.enableMfa(this.userEmail).subscribe({
      next: (response: {qrImage: string, secretKey: string}) => {
        this.qrCodeImage = response.qrImage;
        this.secretKey = response.secretKey;
        this.showMfaSetup = true;
        this.isLoadingMfa = false;
      },
      error: (error: any) => {
        console.error('Error enabling MFA:', error);
        this.isLoadingMfa = false;
      }
    });
  }

  verifyMfaSetup() {
    if (!this.verificationCode || this.verificationCode.length !== 6) {
      this.verificationError = 'Unesite validan 6-cifreni kod';
      return;
    }

    this.isLoadingVerification = true;
    this.verificationError = '';

    this.mfaService.verifyMfa(this.userEmail, this.verificationCode).subscribe({
      next: (response: any) => {
        this.mfaEnabled = true;
        this.showMfaSetup = false;
        this.isLoadingVerification = false;
        this.verificationCode = '';
        this.qrCodeImage = '';
        this.secretKey = '';
        this.verificationError = '';
      },
      error: (error: any) => {
        this.verificationError = error.error || 'Neispravan MFA kod. Pokušajte ponovo.';
        this.isLoadingVerification = false;
      }
    });
  }

  cancelMfaSetup() {
    this.showMfaSetup = false;
    this.qrCodeImage = '';
    this.secretKey = '';
    this.verificationCode = '';
    this.verificationError = '';
  }

  copyToClipboard(input: HTMLInputElement) {
    input.select();
    input.setSelectionRange(0, 99999); // For mobile devices
    document.execCommand('copy');
    
    // Show feedback (you could add a toast notification here)
    const button = input.nextElementSibling as HTMLButtonElement;
    const originalText = button.textContent;
    button.textContent = '✓';
    setTimeout(() => {
      button.textContent = originalText;
    }, 2000);
  }

  logout() {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}