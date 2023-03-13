package com.quackquack.auth.config;

import io.r2dbc.pool.ConnectionPool;
import io.r2dbc.pool.ConnectionPoolConfiguration;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.config.AbstractR2dbcConfiguration;

import java.time.Duration;

import static io.r2dbc.spi.ConnectionFactoryOptions.*;

@Configuration
public class DBConfig extends AbstractR2dbcConfiguration {

    @Value("${db.driver}")
    private String driver;
    @Value("${db.host}")
    private String host;
    @Value("${db.port}")
    private int port;
    @Value("${db.database}")
    private String database;
    @Value("${db.user}")
    private String user;
    @Value("${db.password}")
    private String password;

    @Bean
    @Override
    public ConnectionFactory connectionFactory() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(builder()
                .option(DRIVER, driver)
                .option(HOST, host)
                .option(PORT, port)
                .option(DATABASE, database)
                .option(USER, user)
                .option(PASSWORD, password)
                .build());
        ConnectionPoolConfiguration connectionPoolConfiguration
                = ConnectionPoolConfiguration.builder(connectionFactory)
                .initialSize(2)
                .minIdle(2)
                .maxSize(10)
                .maxLifeTime(Duration.ofSeconds(1800))
                .maxIdleTime(Duration.ofSeconds(1800))
                .build();
        return new ConnectionPool(connectionPoolConfiguration);
    }

}
