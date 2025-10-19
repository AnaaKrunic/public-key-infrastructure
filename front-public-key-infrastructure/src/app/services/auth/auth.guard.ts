import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';
import { Role } from '../../models/Role';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const expectedRoles = route.data['roles'] as Role[];

  console.log('AuthGuard: Checking access to', state.url);
  console.log('AuthGuard: isLoggedIn', authService.isLoggedIn);
  console.log('AuthGuard: userRole', authService.userRole);
  console.log('AuthGuard: expectedRoles', expectedRoles);

  if (authService.isLoggedIn) {
    if (expectedRoles && authService.userRole && !expectedRoles.includes(authService.userRole)) {
      // User is logged in but doesn't have the required role
      console.log('AuthGuard: User role does not match expected roles');
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
    console.log('AuthGuard: Access granted');
    return true; // User is logged in and has the required role (or no specific role required)
  } else {
    console.log('AuthGuard: User not logged in, redirecting to login');
    // User is not logged in, redirect to login page
    return router.createUrlTree(['/login']);
  }
};

export const noAuthGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  console.log('NoAuthGuard: Checking access to', state.url);
  console.log('NoAuthGuard: isLoggedIn', authService.isLoggedIn);
  console.log('NoAuthGuard: userRole', authService.userRole);

  if (authService.isLoggedIn) {
    console.log('NoAuthGuard: User is logged in, redirecting based on role');
    // User is logged in, redirect to home or dashboard based on role
    switch (authService.userRole) {
      case 'ADMIN':
        console.log('NoAuthGuard: Redirecting ADMIN to /admin/certificates');
        return router.createUrlTree(['/admin/certificates']);
      case 'CA_USER':
        console.log('NoAuthGuard: Redirecting CA_USER to /ca/certificates');
        return router.createUrlTree(['/ca/certificates']);
      case 'EE_USER':
        console.log('NoAuthGuard: Redirecting EE_USER to /my-certificates');
        return router.createUrlTree(['/my-certificates']);
      default:
        console.log('NoAuthGuard: No valid role, redirecting to /');
        return router.createUrlTree(['/']);
    }
  }
  console.log('NoAuthGuard: User not logged in, allowing access');
  return true; // User is not logged in, allow access to public routes
};
