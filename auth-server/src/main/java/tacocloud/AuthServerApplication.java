package tacocloud;

import tacocloud.users.User;
import tacocloud.users.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerApplication.class, args);
	}

	@Bean
	public ApplicationRunner dataLoader(UserRepository repo, PasswordEncoder encoder) {
		return args -> {
			repo.save(new User("habuma", encoder.encode("password"), "ROLE_ADMIN"));
			repo.save(new User("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
		};
	}
}

//http://localhost:9000/oauth2/authorize?response_type=code&client_id=tacoadmin-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/taco-admin-client&-scope=writeIngredients+deleteIngredients
