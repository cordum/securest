package tacocloud.repository;

import org.springframework.data.repository.CrudRepository;
import tacocloud.model.Ingredient;

//Spring Data JPA
//<dependency>
//<groupId>org.springframework.boot</groupId>
//<artifactId>spring-boot-starter-data-jpa</artifactId>
//</dependency>
public interface IngredientRepository extends CrudRepository<Ingredient, String> {
}
