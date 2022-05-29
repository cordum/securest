package tacocloud.repository;

import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;
import tacocloud.model.TacoOrder;
import tacocloud.model.User;

import java.util.List;

public interface OrderRepository extends CrudRepository<TacoOrder, Long> {
//    Если аннотация вернет false, метод не выполнится
//    @PreAuthorize("hasRole('ADMIN')")
//    public void deleteAllOrders() {
//        orderRepository.deleteAll();
//    }
//    List<TacoOrder> findByUserOrderByPlacedAtDesc(User user, Pageable pageable);
}