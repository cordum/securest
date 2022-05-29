package tacocloud.model;

import javax.persistence.Entity;
import javax.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;

@Data// генерирует конструктор, геттеры/сеттеры
// @Table необяз аннотация Data Jdbc
@Entity// Объявляем сущностью JPA
// @NoArgsConstructor(access=AccessLevel.PRIVATE, force=true)
// JPA требует, чтобы сущности имели конструктор без аргументов
// но нам не надо, чтобы имелась возможность использовать его, поэтому установим атрибут доступа AccessLevel.PRIVATE
// force = true,значит все final поля инициализируются 0 / false / null
// если это невозможно, то возникает ошибка компиляции
//@RequiredArgsConstructor
// @NoArgsConstructor удаляет конструктор созданный @Data, поэтому генерируем
// конструктор с 1 параметром для каждого поля, которое требует специальной обработки
@AllArgsConstructor// генерирует конструктор с 1 параметром для каждого поля в классе
@NoArgsConstructor(force=true) //access=AccessLevel.PRIVATE,
public class Ingredient {

//    Для Spring Data поля должны быть без final
    @Id// Поле Id для БД
    private String id;
    private String name;
    private Type type;

    public static enum Type {
        WRAP, PROTEIN, VEGGIES, CHEESE, SAUCE
    }
}
