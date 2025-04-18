package fi.haagahelia.taskmanagement.services;

import org.springframework.data.domain.Page;
import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;
import java.util.List;

public interface AdminService {

    // Retrieve all users with employee role
    List<UserDto> getUsers();

    // Create a new user and return the created UserDto
    UserDto createUser(UserDto userDto);

    // Delete a user by their ID
    void deleteUser(Long userId);

    // Create a new task and return the created TaskDto
    TaskDto createTask(TaskDto taskDto);

    // Retrieve all tasks, paginated by the given page number and size
    Page<TaskDto> getAllTasks(int page, int size);

    // Delete a task by its ID
    void deleteTask(Long taskId);

    // Retrieve a task by its ID and return the corresponding TaskDto
    TaskDto getTaskById(Long taskId);

    // Update an existing task and return the updated TaskDto
    TaskDto updateTask(Long taskId, TaskDto taskDto);

    // Search for tasks by title, paginated
    Page<TaskDto> searchTaskByTitle(String title, int page, int size);

    // Create a comment on a task and return the created CommentDto
    CommentDto createComment(Long taskId, String content);

    // Retrieve all comments associated with a specific task, paginated
    Page<CommentDto> getCommentsByTaskId(Long taskId, int page, int size);
}
