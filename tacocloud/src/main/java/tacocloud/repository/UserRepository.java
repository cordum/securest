package tacocloud.repository;

import org.springframework.data.repository.CrudRepository;
import tacocloud.model.User;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}

