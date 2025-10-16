package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApproveCSRDTO {
    
    @NotNull(message = "Validity days is required")
    @Min(value = 1, message = "Validity must be at least 1 day")
    @Max(value = 365, message = "Validity must not exceed 365 days")
    private Integer validityDays;
    
    private Long templateId;
    
    private Map<String, List<String>> additionalExtensions;
}
