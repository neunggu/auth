package com.quackquack.auth.service;

import com.quackquack.auth.exception.AuthException;
import com.quackquack.auth.model.security.AuthResponse;
import com.quackquack.auth.model.security.UserPrincipal;
import com.quackquack.auth.repository.AuthRepository;
import com.quackquack.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityService {

    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthRepository repository;

    public Mono<AuthResponse> findByEmailForAuth(String username, String password, boolean isRefresh) {
        System.out.println(username);
        return repository.findByEmailForAuth(username)
            .flatMap(user -> {
                if (!user.isEnabled())
                    return Mono.error(new AuthException("Account disabled", "ACCOUNT_DISABLED"));
                if (!isRefresh && !passwordEncoder.matches(password, user.getPassword()))
                    return Mono.error(new AuthException("Invalid password", "INVALID"));
                return Mono.just(jwtUtil.generate(user));
            })
            .switchIfEmpty(Mono.error(new AuthException("Invalid user", "INVALID")));
    }

    public Mono<AuthResponse> issueTokenWithRefreshToken(UserPrincipal principal) {
        String username = getValidPrincipal(principal).getName();
        return findByEmailForAuth(username, null, true);
    }

    public UserPrincipal getValidPrincipal(UserPrincipal principal) {
        try {
            String name = jwtUtil.decrypt(principal.getName());
            principal.setName(name);
            return principal;
        } catch (Exception e) {
            log.error(e.toString());
        }
        return null;
    }
}
