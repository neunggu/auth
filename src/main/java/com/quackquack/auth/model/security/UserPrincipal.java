package com.quackquack.auth.model.security;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.Principal;

@Builder
@Getter
@Setter
public class UserPrincipal implements Principal {
    private String name;
}
