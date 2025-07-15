package com.nishanth.UserService.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ValidateTokenRequestDto {
    private Long userId;// pass in path variable
    private String token; // pass in header
}
