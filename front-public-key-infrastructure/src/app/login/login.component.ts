import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { AuthService, LoginDTO } from '../services/auth/auth.service';
import { MfaService } from '../services/mfa.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, ReactiveFormsModule, RouterModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  loginForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  showMfaField = false;
  requiresMfa = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private mfaService: MfaService
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
      mfaCode: ['']
    });
  }

  onSubmit() {
    console.log('LoginComponent.onSubmit: Form submitted');
    console.log('LoginComponent.onSubmit: Form valid:', this.loginForm.valid);
    console.log('LoginComponent.onSubmit: Form value:', this.loginForm.value);
    
    if (this.loginForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';

      const credentials: LoginDTO = this.loginForm.value;
      console.log('LoginComponent.onSubmit: Calling authService.login with:', credentials);
      console.log('LoginComponent.onSubmit: AuthService instance:', this.authService);
      console.log('LoginComponent.onSubmit: AuthService login method:', this.authService.login);

      this.authService.login(credentials).subscribe({
        next: (response: any) => {
          console.log('LoginComponent.onSubmit: Login successful, response:', response);
          this.isLoading = false;
          // Store tokens and user data are handled in the service
          // Now we can safely navigate as user data is loaded
          console.log('LoginComponent.onSubmit: Navigating to /dashboard');
          this.router.navigate(['/dashboard']);
        },
        error: (error: any) => {
          console.log('Login error:', error);
          
          // Extract error message safely
          let errorMessage = 'Greška prilikom prijave. Proverite podatke i pokušajte ponovo.';
          
          if (error.error) {
            if (typeof error.error === 'string') {
              errorMessage = error.error;
            } else if (error.error.message) {
              errorMessage = error.error.message;
            }
          } else if (error.message) {
            errorMessage = error.message;
          }
          
          // Check if MFA is required
          if (errorMessage.includes('MFA')) {
            this.requiresMfa = true;
            this.showMfaField = true;
            this.loginForm.get('mfaCode')?.setValidators([Validators.required]);
            this.loginForm.get('mfaCode')?.updateValueAndValidity();
            this.errorMessage = 'Unesite MFA kod da završite prijavu.';
          } else {
            this.errorMessage = errorMessage;
          }
          this.isLoading = false;
        }
      });
    } else {
      console.log('LoginComponent.onSubmit: Form is invalid, marking fields as touched');
      this.markFormGroupTouched();
    }
  }

  private markFormGroupTouched() {
    Object.keys(this.loginForm.controls).forEach(key => {
      const control = this.loginForm.get(key);
      control?.markAsTouched();
    });
  }

  goToRegistration() {
    this.router.navigate(['/registration']);
  }

  getFieldError(fieldName: string): string {
    const field = this.loginForm.get(fieldName);
    if (field?.errors && field.touched) {
      if (field.errors['required']) {
        return `${this.getFieldLabel(fieldName)} je obavezno polje.`;
      }
      if (field.errors['email']) {
        return 'Unesite validnu email adresu.';
      }
    }
    return '';
  }

  private getFieldLabel(fieldName: string): string {
    const labels: { [key: string]: string } = {
      email: 'Email',
      password: 'Lozinka'
    };
    return labels[fieldName] || fieldName;
  }
}
