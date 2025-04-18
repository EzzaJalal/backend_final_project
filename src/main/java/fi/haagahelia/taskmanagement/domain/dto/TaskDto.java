package fi.haagahelia.taskmanagement.domain.dto;

import java.sql.Date;

import fi.haagahelia.taskmanagement.domain.TaskStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class TaskDto {

    // Unique identifier for the task
    private Long id;

    // Title of the task, must not be blank
    @NotBlank(message = "Title is required")
    private String title;

    // Optional description of the task
    private String description;

    // Due date for the task, must not be null
    @NotNull(message = "Due date is required")
    private Date dueDate;

    // Priority level of the task, must not be blank
    @NotBlank(message = "Priority is required")
    private String priority;

    // Current status of the task (e.g., PENDING, COMPLETED)
    private TaskStatus taskStatus;

    // ID of the employee assigned to this task
    private Long employeeId;

    // Name of the employee assigned to this task
    private String employeeName;

    // Constructor used for DTO projection in custom queries
    public TaskDto(Long id, String title, String description, Date dueDate, String priority,
            TaskStatus taskStatus, Long employeeId, String employeeName) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.dueDate = dueDate;
        this.priority = priority;
        this.taskStatus = taskStatus;
        this.employeeId = employeeId;
        this.employeeName = employeeName;
    }
}
