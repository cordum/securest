package tacocloud.repository;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import tacocloud.model.Taco;

import java.net.ContentHandler;

public interface TacoRepository extends PagingAndSortingRepository<Taco, Long> {//CrudRepository<Taco, Long> {
}
