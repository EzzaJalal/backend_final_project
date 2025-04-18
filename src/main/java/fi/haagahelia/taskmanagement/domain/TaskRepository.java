package fi.haagahelia.taskmanagement.domain;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import fi.haagahelia.taskmanagement.domain.dto.TaskDto;

/**
 * Repository interface for Task entity with search and DTO projections.
 */
@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {

        /** Find tasks by partial title match (case-insensitive) */
        Page<Task> findAllByTitleContainingIgnoreCase(String title, Pageable pageable);

        /** Find tasks assigned to a specific user */
        Page<Task> findAllByUserId(Long userId, Pageable pageable);

        /** Fetch all tasks with user data eagerly loaded */
        @Query("SELECT t FROM Task t JOIN FETCH t.user ORDER BY t.dueDate DESC")
        Page<Task> findAllWithUser(Pageable pageable);

        /** Fetch tasks by title with user data eagerly loaded */
        @Query("SELECT t FROM Task t JOIN FETCH t.user WHERE UPPER(t.title) LIKE UPPER(CONCAT('%', :title, '%')) ORDER BY t.dueDate DESC")
        Page<Task> findAllByTitleContainingIgnoreCaseWithUser(String title, Pageable pageable);

        /** Return DTO projection of tasks by user ID */
        @Query("SELECT new fi.haagahelia.taskmanagement.domain.dto.TaskDto(" +
                        "t.id, t.title, t.description, t.dueDate, t.priority, t.taskStatus, u.id, u.name) " +
                        "FROM Task t JOIN t.user u WHERE u.id = :userId ORDER BY t.dueDate DESC")
        Page<TaskDto> findTaskDtosByUserId(@Param("userId") Long userId, Pageable pageable);

        /** Return a single task as DTO by its ID */
        @Query("SELECT new fi.haagahelia.taskmanagement.domain.dto.TaskDto(" +
                        "t.id, t.title, t.description, t.dueDate, t.priority, t.taskStatus, u.id, u.name) " +
                        "FROM Task t JOIN t.user u WHERE t.id = :taskId")
        TaskDto findTaskDtoById(@Param("taskId") Long taskId);
}
