import { Injectable, inject } from '@angular/core';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DialogService {
  private dialog = inject(MatDialog);

  /**
   * Opens a dialog with proper cleanup handling
   */
  openDialog<T, D = any, R = any>(
    component: any,
    config: {
      width?: string;
      maxWidth?: string;
      maxHeight?: string;
      data?: D;
      disableClose?: boolean;
      autoFocus?: boolean;
    } = {}
  ): MatDialogRef<T, R> {
    const dialogRef = this.dialog.open<T, D, R>(component, {
      width: config.width || '600px',
      maxWidth: config.maxWidth || '90vw',
      maxHeight: config.maxHeight || '90vh',
      data: config.data,
      disableClose: config.disableClose || false,
      autoFocus: config.autoFocus !== false,
      hasBackdrop: true,
      backdropClass: 'cdk-overlay-backdrop'
    });

    // Ensure proper cleanup
    dialogRef.afterClosed().subscribe(() => {
      this.cleanupOverlays();
    });

    return dialogRef;
  }

  /**
   * Cleans up any stuck overlays
   */
  cleanupOverlays(): void {
    // Small delay to ensure Angular has processed the close
    setTimeout(() => {
      const overlayContainers = document.querySelectorAll('.cdk-overlay-container');
      console.log('Cleanup: Found', overlayContainers.length, 'overlay containers');
      
      overlayContainers.forEach((container, index) => {
        const panes = container.querySelectorAll('.cdk-overlay-pane');
        const backdrops = container.querySelectorAll('.cdk-overlay-backdrop');
        
        console.log(`Cleanup: Container ${index} has ${panes.length} panes and ${backdrops.length} backdrops`);
        
        // Only remove elements that are definitely not showing
        panes.forEach(pane => {
          if (!pane.classList.contains('cdk-overlay-pane-showing') && 
              !pane.classList.contains('cdk-overlay-pane-showing-animating')) {
            console.log('Cleanup: Removing non-showing pane');
            pane.remove();
          }
        });
        
        backdrops.forEach(backdrop => {
          if (!backdrop.classList.contains('cdk-overlay-backdrop-showing') && 
              !backdrop.classList.contains('cdk-overlay-backdrop-showing-animating')) {
            console.log('Cleanup: Removing non-showing backdrop');
            backdrop.remove();
          }
        });
        
        // NEW APPROACH: Don't remove the container, just clear its contents
        if (container.children.length === 0) {
          console.log('Cleanup: Container is empty, keeping it for reuse');
          // Don't remove the container - Angular Material might need it
        } else {
          console.log('Cleanup: Container still has', container.children.length, 'children');
        }
      });
    }, 200); // Increased delay to be safer
  }

  /**
   * Force cleanup all overlays (emergency method) - but keep containers
   */
  forceCleanup(): void {
    console.log('Force cleanup: Starting emergency cleanup');
    
    // Remove any stuck backdrop elements
    const stuckBackdrops = document.querySelectorAll('.cdk-overlay-backdrop');
    console.log('Force cleanup: Removing', stuckBackdrops.length, 'stuck backdrops');
    stuckBackdrops.forEach(backdrop => backdrop.remove());
    
    // Remove any stuck pane elements
    const stuckPanes = document.querySelectorAll('.cdk-overlay-pane');
    console.log('Force cleanup: Removing', stuckPanes.length, 'stuck panes');
    stuckPanes.forEach(pane => pane.remove());
    
    // DON'T remove containers - Angular Material needs them
    const overlayContainers = document.querySelectorAll('.cdk-overlay-container');
    console.log('Force cleanup: Keeping', overlayContainers.length, 'overlay containers for reuse');
  }

  /**
   * Reset overlay container state - only remove problematic elements
   */
  resetOverlayState(): void {
    console.log('Reset: Starting selective overlay state reset');
    
    // Only remove non-showing elements, keep containers
    const overlayContainers = document.querySelectorAll('.cdk-overlay-container');
    console.log('Reset: Found', overlayContainers.length, 'overlay containers');
    
    overlayContainers.forEach((container, index) => {
      const panes = container.querySelectorAll('.cdk-overlay-pane');
      const backdrops = container.querySelectorAll('.cdk-overlay-backdrop');
      
      console.log(`Reset: Container ${index} has ${panes.length} panes and ${backdrops.length} backdrops`);
      
      // Remove non-showing elements
      panes.forEach(pane => {
        if (!pane.classList.contains('cdk-overlay-pane-showing') && 
            !pane.classList.contains('cdk-overlay-pane-showing-animating')) {
          console.log('Reset: Removing non-showing pane');
          pane.remove();
        }
      });
      
      backdrops.forEach(backdrop => {
        if (!backdrop.classList.contains('cdk-overlay-backdrop-showing') && 
            !backdrop.classList.contains('cdk-overlay-backdrop-showing-animating')) {
          console.log('Reset: Removing non-showing backdrop');
          backdrop.remove();
        }
      });
      
      // NEW APPROACH: Keep containers, even if empty
      if (container.children.length === 0) {
        console.log('Reset: Container is empty, keeping it for reuse');
        // Don't remove the container - Angular Material might need it
      } else {
        console.log('Reset: Container still has', container.children.length, 'children');
      }
    });
    
    // Final check
    const finalCheck = document.querySelectorAll('.cdk-overlay-container, .cdk-overlay-backdrop, .cdk-overlay-pane');
    console.log('Reset: Final check - remaining elements:', finalCheck.length);
  }
}
