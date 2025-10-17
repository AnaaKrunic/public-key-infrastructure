import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';
import { Role } from '../../models/Role';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const expectedRoles = route.data['roles'] as Role[];

  if (authService.isLoggedIn) {
    if (expectedRoles && authService.userRole && !expectedRoles.includes(authService.userRole)) {
      // User is logged in but doesn't have the required role
      // Redirect to a role-specific dashboard or access denied page
      switch (authService.userRole) {
        case 'ADMIN':
          return router.createUrlTree(['/admin/certificates']);
        case 'CA_USER':
          return router.createUrlTree(['/ca/certificates']);
        case 'EE_USER':
          return router.createUrlTree(['/my-certificates']);
        default:
          return router.createUrlTree(['/access-denied']);
      }
    }
    return true; // User is logged in and has the required role (or no specific role required)
  } else {
    // User is not logged in, redirect to login page
    return router.createUrlTree(['/login']);
  }
};

export const noAuthGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn) {
    // User is logged in, redirect to home or dashboard based on role
    switch (authService.userRole) {
      case 'ADMIN':
        return router.createUrlTree(['/admin/certificates']);
      case 'CA_USER':
        return router.createUrlTree(['/ca/certificates']);
      case 'EE_USER':
        return router.createUrlTree(['/my-certificates']);
      default:
        return router.createUrlTree(['/']);
    }
  }
  return true; // User is not logged in, allow access to public routes
};
