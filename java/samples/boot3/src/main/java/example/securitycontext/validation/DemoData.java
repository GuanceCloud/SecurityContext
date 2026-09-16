package example.securitycontext.validation;

import javax.sql.DataSource;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.Statement;

@Configuration
public class DemoData {
    @Bean
    CommandLineRunner initialize(DataSource dataSource) {
        return args -> {
            try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
                statement.execute("CREATE TABLE IF NOT EXISTS demo_users (name VARCHAR(128))");
                statement.execute("INSERT INTO demo_users(name) SELECT 'guest' WHERE NOT EXISTS (SELECT 1 FROM demo_users)");
            }
        };
    }
}
