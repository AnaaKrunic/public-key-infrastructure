import { Component, Inject, PLATFORM_ID } from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService, UserRegistrationDTO } from '../services/auth.service';

@Component({
  selector: 'app-registration',
  standalone: true,
  imports: [CommonModule, FormsModule, ReactiveFormsModule],
  templateUrl: './registration.component.html',
  styleUrl: './registration.component.css'
})
export class RegistrationComponent {
  registrationForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  passwordStrength = {
    score: 0,
    label: '',
    color: ''
  };

  passwordChecks = {
    length: false,
    lowercase: false,
    uppercase: false,
    number: false,
    special: false
  };

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    this.registrationForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8), this.passwordComplexityValidator]],
      confirmPassword: ['', [Validators.required]],
      firstName: ['', [Validators.required, Validators.minLength(2)]],
      lastName: ['', [Validators.required, Validators.minLength(2)]],
      organization: ['', [Validators.required, Validators.minLength(2)]]
    }, { validators: this.passwordMatchValidator });
  }

  passwordMatchValidator(form: FormGroup) {
    const password = form.get('password');
    const confirmPassword = form.get('confirmPassword');
    
    if (password && confirmPassword && password.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true });
      return { passwordMismatch: true };
    }
    
    if (confirmPassword?.errors?.['passwordMismatch']) {
      delete confirmPassword.errors['passwordMismatch'];
      if (Object.keys(confirmPassword.errors).length === 0) {
        confirmPassword.setErrors(null);
      }
    }
    
    return null;
  }

  passwordComplexityValidator(control: any) {
    if (!control.value) return null;
    
    const password = control.value;
    const hasLowercase = /[a-z]/.test(password);
    const hasUppercase = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[@$!%*?&]/.test(password);
    
    if (!hasLowercase || !hasUppercase || !hasNumber || !hasSpecial) {
      return { passwordComplexity: true };
    }
    
    return null;
  }

  onPasswordChange() {
    const password = this.registrationForm.get('password')?.value;
    if (password && password.length > 0) {
      this.calculatePasswordStrength(password);
    } else {
      // Reset password strength when field is empty
      this.passwordStrength = { score: 0, label: '', color: '' };
      this.passwordChecks = {
        length: false,
        lowercase: false,
        uppercase: false,
        number: false,
        special: false
      };
    }
    // Trigger validation for confirm password
    this.registrationForm.get('confirmPassword')?.updateValueAndValidity();
  }

  calculatePasswordStrength(password: string) {
    let score = 0;
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[@$!%*?&]/.test(password)
    };

    // Update password checks for template
    this.passwordChecks = checks;

    // Calculate score
    Object.values(checks).forEach(check => {
      if (check) score++;
    });

    // Determine strength level
    if (score < 3) {
      this.passwordStrength = { score, label: 'Slaba', color: '#dc3545' };
    } else if (score < 5) {
      this.passwordStrength = { score, label: 'Srednja', color: '#ffc107' };
    } else {
      this.passwordStrength = { score, label: 'Jaka', color: '#28a745' };
    }
  }

  onSubmit() {
    if (this.registrationForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      this.successMessage = '';

      const formData: UserRegistrationDTO = this.registrationForm.value;

      this.authService.register(formData).subscribe({
        next: (response: any) => {
          this.successMessage = 'Uspešno ste se registrovali! Proverite email za aktivaciju naloga.';
          this.isLoading = false;
          // Optionally redirect to login after successful registration
          setTimeout(() => {
            this.router.navigate(['/login']);
          }, 3000);
        },
        error: (error: any) => {
          this.errorMessage = error.error || 'Greška prilikom registracije. Pokušajte ponovo.';
          this.isLoading = false;
        }
      });
    } else {
      this.markFormGroupTouched();
    }
  }

  private markFormGroupTouched() {
    Object.keys(this.registrationForm.controls).forEach(key => {
      const control = this.registrationForm.get(key);
      control?.markAsTouched();
    });
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }

  getFieldError(fieldName: string): string {
    const field = this.registrationForm.get(fieldName);
    if (field?.errors && field.touched) {
      if (field.errors['required']) {
        return `${this.getFieldLabel(fieldName)} je obavezno polje.`;
      }
      if (field.errors['email']) {
        return 'Unesite validnu email adresu.';
      }
      if (field.errors['minlength']) {
        return `${this.getFieldLabel(fieldName)} mora imati najmanje ${field.errors['minlength'].requiredLength} karaktera.`;
      }
      if (field.errors['passwordMismatch']) {
        return 'Lozinke se ne poklapaju.';
      }
      if (field.errors['passwordComplexity']) {
        return 'Lozinka mora sadržavati najmanje jedno malo slovo, jedno veliko slovo, jedan broj i jedan specijalni karakter (@$!%*?&).';
      }
    }
    return '';
  }

  private getFieldLabel(fieldName: string): string {
    const labels: { [key: string]: string } = {
      email: 'Email',
      password: 'Lozinka',
      confirmPassword: 'Potvrda lozinke',
      firstName: 'Ime',
      lastName: 'Prezime',
      organization: 'Organizacija'
    };
    return labels[fieldName] || fieldName;
  }
}
