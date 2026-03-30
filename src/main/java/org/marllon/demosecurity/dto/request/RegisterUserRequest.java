package org.marllon.demosecurity.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record RegisterUserRequest(@NotEmpty(message = "Nome, não pode estar vazio") String name,
                                  @NotEmpty(message = "Email, não pode estar vazio")String email,
                                  @NotEmpty(message = "Senha, não pode estar vazio")String password) {
}
