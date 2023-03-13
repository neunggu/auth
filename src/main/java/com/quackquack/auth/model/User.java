package com.quackquack.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.quackquack.auth.model.security.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private static final long serialVersionUID = 1L;

    private String id;
    private String username;
    private String password;
    private boolean enabled;
    private List<Role> roles;
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(authority -> new SimpleGrantedAuthority(authority.name())).collect(Collectors.toList());
    }
}