package tacocloud.model;

import lombok.Data;
import org.springframework.data.rest.core.annotation.RestResource;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
@Entity
//@Table
// Relation name and path
// Иначе путь будет /data-api/tacoes
@RestResource(rel="tacos", path="tacos")
public class Taco {

    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)// Авто генерация Id
    private Long id;

    // Валидация
    @NotNull// Поле не должно быть пустым
    @Size(min=5, message="Name must be at least 5 characters long")//не менее 5 символов
    private String name;

    private Date createdAt = new Date();

    @Size(min=1, message="You must choose at least 1 ingredient")
    // Taco может иметь много объектов Ingredient и Ingredient может быть частью многих Taco
    @ManyToMany(targetEntity=Ingredient.class)
    private List<Ingredient> ingredients = new ArrayList<>();

    public void addIngredient(Ingredient ingredient) {
        this.ingredients.add(ingredient);
    }
}
