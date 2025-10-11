import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-activation',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './activation.component.html',
  styleUrls: ['./activation.component.css']
})
export class ActivationComponent implements OnInit {
  isLoading = false;
  message = '';
  isSuccess = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const token = params['token'];
      if (token) {
        this.activateAccount(token);
      } else {
        this.message = 'Invalid activation link.';
        this.isSuccess = false;
      }
    });
  }

  activateAccount(token: string) {
    this.isLoading = true;
    this.authService.activateAccount(token).subscribe({
      next: (response: any) => {
        this.message = 'Account activated successfully! You can now log in.';
        this.isSuccess = true;
        this.isLoading = false;
        
        // Redirect to login after 3 seconds
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 3000);
      },
      error: (error: any) => {
        this.message = error.error || 'Activation failed. Please try again.';
        this.isSuccess = false;
        this.isLoading = false;
      }
    });
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }

  goToRegistration() {
    this.router.navigate(['/registration']);
  }
}
