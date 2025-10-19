import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { TemplateService } from '../../../services/template/template.service';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Template, CreateTemplateDTO } from '../../../models/Template';
import { Certificate } from '../../../models/Certificate';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-template-management',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './template-management.component.html',
  styleUrls: ['./template-management.component.css']
})
export class TemplateManagementComponent implements OnInit {
  templates: Template[] = [];
  availableCAs: Certificate[] = [];
  templateForm: FormGroup;
  isCreating = false;
  editingTemplate: Template | null = null;

  constructor(
    private templateService: TemplateService,
    private certificatesService: CertificatesService,
    private fb: FormBuilder,
    private toastr: ToastrService
  ) {
    this.templateForm = this.fb.group({
      name: ['', [Validators.required, Validators.maxLength(100)]],
      caIssuerSerialNumber: ['', Validators.required],
      cnRegex: ['', [Validators.required, Validators.maxLength(500)]],
      sanRegex: ['', [Validators.required, Validators.maxLength(500)]],
      ttl: [365, [Validators.required, Validators.min(1), Validators.max(3650)]],
      keyUsage: ['', [Validators.required, Validators.maxLength(500)]],
      extendedKeyUsage: ['', [Validators.required, Validators.maxLength(500)]]
    });
  }

  ngOnInit() {
    this.loadTemplates();
    this.loadAvailableCAs();
  }

  loadTemplates() {
    this.templateService.getAllTemplates().subscribe({
      next: (templates) => {
        this.templates = templates;
      },
      error: (error) => {
        this.toastr.error('Failed to load templates', 'Error');
        console.error('Error loading templates:', error);
      }
    });
  }

  loadAvailableCAs() {
    this.certificatesService.getAllCertificates().subscribe({
      next: (certificates) => {
        // Filter only CA certificates (ROOT and INTERMEDIATE)
        this.availableCAs = certificates.filter(cert => 
          cert.type === 'ROOT' || cert.type === 'INTERMEDIATE'
        );
      },
      error: (error) => {
        this.toastr.error('Failed to load CA certificates', 'Error');
        console.error('Error loading CA certificates:', error);
      }
    });
  }

  createTemplate() {
    if (this.templateForm.valid) {
      this.isCreating = true;
      const dto: CreateTemplateDTO = this.templateForm.value;
      
      this.templateService.createTemplate(dto).subscribe({
        next: (template) => {
          this.templates.push(template);
          this.templateForm.reset();
          this.templateForm.patchValue({ ttl: 365 }); // Reset to default
          this.isCreating = false;
          this.toastr.success('Template created successfully', 'Success');
        },
        error: (error) => {
          this.isCreating = false;
          this.toastr.error(error.error?.error || 'Failed to create template', 'Error');
          console.error('Error creating template:', error);
        }
      });
    } else {
      this.toastr.warning('Please fill in all required fields', 'Validation Error');
    }
  }

  editTemplate(template: Template) {
    this.editingTemplate = template;
    this.templateForm.patchValue({
      name: template.name,
      cnRegex: template.cnRegex,
      sanRegex: template.sanRegex,
      ttl: template.ttl,
      keyUsage: template.keyUsage,
      extendedKeyUsage: template.extendedKeyUsage
    });
  }

  updateTemplate() {
    if (this.templateForm.valid && this.editingTemplate) {
      const dto = {
        name: this.templateForm.value.name,
        cnRegex: this.templateForm.value.cnRegex,
        sanRegex: this.templateForm.value.sanRegex,
        ttl: this.templateForm.value.ttl,
        keyUsage: this.templateForm.value.keyUsage,
        extendedKeyUsage: this.templateForm.value.extendedKeyUsage
      };
      
      this.templateService.updateTemplate(this.editingTemplate.id, dto).subscribe({
        next: (updatedTemplate) => {
          const index = this.templates.findIndex(t => t.id === updatedTemplate.id);
          if (index !== -1) {
            this.templates[index] = updatedTemplate;
          }
          this.cancelEdit();
          this.toastr.success('Template updated successfully', 'Success');
        },
        error: (error) => {
          this.toastr.error(error.error?.error || 'Failed to update template', 'Error');
          console.error('Error updating template:', error);
        }
      });
    }
  }

  deleteTemplate(template: Template) {
    if (confirm(`Are you sure you want to delete template "${template.name}"?`)) {
      this.templateService.deleteTemplate(template.id).subscribe({
        next: () => {
          this.templates = this.templates.filter(t => t.id !== template.id);
          this.toastr.success('Template deleted successfully', 'Success');
        },
        error: (error) => {
          this.toastr.error(error.error?.error || 'Failed to delete template', 'Error');
          console.error('Error deleting template:', error);
        }
      });
    }
  }

  cancelEdit() {
    this.editingTemplate = null;
    this.templateForm.reset();
    this.templateForm.patchValue({ ttl: 365 });
  }

  testRegex(pattern: string, testValue: string): boolean {
    try {
      const regex = new RegExp(pattern);
      return regex.test(testValue);
    } catch (e) {
      return false;
    }
  }

  getFormControl(name: string) {
    return this.templateForm.get(name);
  }
}
