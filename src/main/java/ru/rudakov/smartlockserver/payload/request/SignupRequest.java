package ru.rudakov.smartlockserver.payload.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;

@Data
public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;
    private Set<String> role;
    @NotBlank
    @Size(min = 4, max = 20)
    private String password;
}