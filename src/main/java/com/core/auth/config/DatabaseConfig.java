package com.core.auth.config;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;

/**
 * @author Roeurt Kesei
 * Database configuration class to initialize the database schema and seed data
 */
@Configuration
public class DatabaseConfig {

    @Bean
    @ConditionalOnProperty(prefix = "app.db", name = "init", havingValue = "true", matchIfMissing = false)
    public ConnectionFactoryInitializer databaseInitializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer initializer = new ConnectionFactoryInitializer();
        initializer.setConnectionFactory(connectionFactory);
        
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("db/migration/schema.sql"));
        populator.addScript(new ClassPathResource("db/migration/data.sql"));
        populator.setContinueOnError(true);
        
        initializer.setDatabasePopulator(populator);
        return initializer;
    }

    @Bean
    @ConditionalOnProperty(prefix = "app.db", name = "init", havingValue = "true", matchIfMissing = false)
    public CommandLineRunner initCheck() {
        return args -> {
            System.out.println("✅ Database initialization completed!");
        };
    }
}