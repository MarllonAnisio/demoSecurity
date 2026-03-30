package org.marllon.demosecurity.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record LoginRequest(@NotEmpty(message = "Email é Obrigatorio") String email,
        @NotEmpty(message = "Senha é Obrigatoria") String password) {
}
