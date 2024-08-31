package cn.piao888.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication(scanBasePackages = "cn.piao888.user")
//@SpringBootApplication
@EnableWebSecurity
public class AuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}
