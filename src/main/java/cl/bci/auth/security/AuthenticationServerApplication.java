package cl.bci.auth.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@SpringBootApplication
@Transactional(propagation=Propagation.NEVER)
public class AuthenticationServerApplication {

    public static void main(String... args) {
        SpringApplication.run(AuthenticationServerApplication.class, args);
    }

}
