package fi.haagahelia.taskmanagement.services;

import org.springframework.data.domain.Page;

import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;

/**
 * Interface for defining services available to an employee.
 * This service is designed to allow employees to interact with their tasks,
 * update task statuses, add comments, and retrieve task information.
 */
public interface EmployeeService {

    /**
     * Retrieves a paginated list of tasks assigned to the currently logged-in
     * employee.
     * 
     * @param page The page number to fetch.
     * @param size The size of each page.
     * @return A paginated list of Task DTOs for the logged-in user.
     */
    Page<TaskDto> getTasksByUserId(int page, int size);

    /**
     * Updates the status of a specific task assigned to the logged-in employee.
     * 
     * @param taskId The ID of the task to update.
     * @param status The new status of the task.
     * @return The updated Task DTO.
     */
    TaskDto updateTask(Long taskId, String status);

    /**
     * Updates a specific task with new details such as title, description, due
     * date, etc.
     * 
     * @param taskId  The ID of the task to update.
     * @param taskDto DTO containing the updated task information.
     * @return The updated Task DTO.
     */
    TaskDto updateTask(Long taskId, TaskDto taskDto);

    /**
     * Creates a comment on a task assigned to the logged-in employee.
     * 
     * @param taskId  The ID of the task to comment on.
     * @param content The content of the comment.
     * @return The created Comment DTO.
     */
    CommentDto createComment(Long taskId, String content);

    /**
     * Retrieves a paginated list of comments for a specific task.
     * 
     * @param taskId The ID of the task for which to fetch comments.
     * @param page   The page number to fetch.
     * @param size   The size of each page.
     * @return A paginated list of Comment DTOs for the task.
     */
    Page<CommentDto> getCommentsByTaskId(Long taskId, int page, int size);

    /**
     * Retrieves the details of a specific task by its ID.
     * 
     * @param taskId The ID of the task to retrieve.
     * @return The Task DTO with the task details.
     */
    TaskDto getTaskById(Long taskId);
}
