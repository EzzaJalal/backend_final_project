package fi.haagahelia.taskmanagement.domain;

import java.sql.Date;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import com.fasterxml.jackson.annotation.JsonIgnore;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import jakarta.persistence.*;
import lombok.Data;

/**
 * Represents a task assigned to a user.
 * Contains status, priority, description, and due date.
 */
@Entity
@Data
@Table(name = "task")
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Task title */
    private String title;

    /** Task description */
    private String description;

    /** Due date of the task */
    private Date dueDate;

    /** Priority level (e.g., High, Medium, Low) */
    private String priority;

    /** Status of the task (enum: PENDING, INPROGRESS, etc.) */
    @Enumerated(EnumType.STRING)
    private TaskStatus taskStatus;

    /** The user (employee) assigned to this task */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    private User user;

    /**
     * Converts this Task entity to a TaskDto for API use.
     *
     * @return TaskDto with full data
     */
    public TaskDto getTaskDto() {
        TaskDto taskDto = new TaskDto();
        taskDto.setId(id);
        taskDto.setTitle(title);
        taskDto.setDescription(description);
        taskDto.setDueDate(dueDate);
        taskDto.setPriority(priority);
        taskDto.setTaskStatus(taskStatus);
        taskDto.setEmployeeId(user.getId());
        taskDto.setEmployeeName(user.getName());
        return taskDto;
    }
}
