package com.quackquack.auth.repository;
import com.quackquack.auth.model.User;
import com.quackquack.auth.model.security.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Repository
@RequiredArgsConstructor
public class AuthRepository {

    private final DatabaseClient databaseClient;

    public Mono<User> findByEmailForAuth(String email) {
        String query =
            """
                SELECT u.id, u.email as 'username', u.pwd as 'password'
                    , if(u.user_type='B', 'false', 'true') as 'enabled'
                    , ifnull(ur.role,'USER') as 'role'
                FROM user u
                LEFT JOIN user_role ur
                ON u.id = ur.user_id
                WHERE u.email = :email
            """;
        return Mono.from(databaseClient.sql(query)
                .bind("email", email)
                .fetch().all()
                .bufferUntilChanged(result -> result.get("id"))
                .map(result-> returnUser(result)));
    }

    private User returnUser(List<Map<String, Object>> result){
        var roles = result.stream()
                .map(row-> Role.valueOf((String) row.get("role")))
                .toList();
        var row = result.get(0);
        return User.builder()
                .id((String) row.get("id"))
                .username((String) row.get("username"))
                .password((String) row.get("password"))
                .enabled(Boolean.valueOf((String) row.get("enabled")))
                .roles(roles)
                .build();
    }
}
