package com.quackquack.auth.controller;

import com.quackquack.auth.model.security.AuthRequest;
import com.quackquack.auth.model.security.AuthResponse;
import com.quackquack.auth.model.security.UserPrincipal;
import com.quackquack.auth.service.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final SecurityService securityService;

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest ar) {
        return securityService.findByEmailForAuth(ar.getUsername(), ar.getPassword(), false)
            .flatMap(response->Mono.just(ResponseEntity.ok(response)))
            .onErrorReturn(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @GetMapping("/valid")
    public Mono<ResponseEntity> valid(Authentication authentication) {
        if (ObjectUtils.isEmpty(authentication))
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        UserPrincipal principal = securityService.getValidPrincipal((UserPrincipal) authentication.getPrincipal());
        return Mono.just(ResponseEntity.ok(principal));
    }

    @GetMapping("/refresh")
    public Mono<ResponseEntity<AuthResponse>> refresh(Authentication authentication) {
        if (ObjectUtils.isEmpty(authentication))
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        return securityService.issueTokenWithRefreshToken((UserPrincipal) authentication.getPrincipal())
                .flatMap(response->Mono.just(ResponseEntity.ok(response)))
                .onErrorReturn(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

}
