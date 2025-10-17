package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ValidCAUserDTO {
    
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String organization;
    private LocalDateTime minValidFrom;
    private LocalDateTime maxValidUntil;
}
