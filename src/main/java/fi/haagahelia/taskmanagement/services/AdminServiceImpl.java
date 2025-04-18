package fi.haagahelia.taskmanagement.services;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import fi.haagahelia.taskmanagement.domain.Comment;
import fi.haagahelia.taskmanagement.domain.CommentRepository;
import fi.haagahelia.taskmanagement.domain.Task;
import fi.haagahelia.taskmanagement.domain.TaskRepository;
import fi.haagahelia.taskmanagement.domain.TaskStatus;
import fi.haagahelia.taskmanagement.domain.User;
import fi.haagahelia.taskmanagement.domain.UserRepository;
import fi.haagahelia.taskmanagement.domain.UserRole;
import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;
import fi.haagahelia.taskmanagement.utils.JwtUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    // Dependencies injected via constructor-based dependency injection
    private final UserRepository userRepository;
    private final TaskRepository taskRepository;
    private final JwtUtil jwtUtil;
    private final CommentRepository commentRepository;

    // Retrieve all users with employee role and return as list of UserDto objects
    @Override
    public List<UserDto> getUsers() {
        return userRepository.findAll().stream()
                .filter(user -> user.getUserRole() == UserRole.EMPLOYEE) // Only include employees
                .map(user -> {
                    UserDto dto = user.getUserDto();
                    dto.setVerified(user.isVerified()); // Set verified status
                    return dto;
                })
                .collect(Collectors.toList());
    }

    // Create a new user, hash the password, set default role, and return UserDto
    @Override
    public UserDto createUser(UserDto userDto) {
        User user = new User();
        user.setName(userDto.getName());
        user.setEmail(userDto.getEmail());
        user.setPassword(new BCryptPasswordEncoder().encode(userDto.getPassword()));
        user.setUserRole(userDto.getUserRole() != null ? userDto.getUserRole() : UserRole.EMPLOYEE); // Default to
                                                                                                     // EMPLOYEE if no
                                                                                                     // role provided
        user.setVerified(true); // Automatically verify users created by admin
        User savedUser = userRepository.save(user);
        return savedUser.getUserDto(); // Return DTO representation of the saved user
    }

    // Delete a user by their ID
    @Override
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    // Create a task, associate it with an employee, and return TaskDto
    @Override
    public TaskDto createTask(TaskDto taskDto) {
        Optional<User> optionalUser = userRepository.findById(taskDto.getEmployeeId());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            Task task = new Task();
            task.setTitle(taskDto.getTitle());
            task.setDescription(taskDto.getDescription());
            task.setDueDate(taskDto.getDueDate());
            task.setPriority(taskDto.getPriority());
            task.setTaskStatus(TaskStatus.INPROGRESS); // Default status is INPROGRESS
            task.setUser(user); // Associate task with employee
            Task savedTask = taskRepository.save(task);
            return savedTask.getTaskDto(); // Return DTO representation of the saved task
        }
        return null; // Return null if the user was not found
    }

    // Retrieve all tasks, paginated by page number and size, sorted by due date
    // descending
    @Override
    public Page<TaskDto> getAllTasks(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("dueDate").descending());
        Page<Task> taskPage = taskRepository.findAllWithUser(pageRequest);
        List<TaskDto> taskDtos = taskPage.getContent().stream()
                .map(Task::getTaskDto) // Convert Task to TaskDto
                .collect(Collectors.toList());
        return new PageImpl<>(taskDtos, pageRequest, taskPage.getTotalElements());
    }

    // Delete a task by its ID
    @Override
    public void deleteTask(Long taskId) {
        taskRepository.deleteById(taskId);
    }

    // Retrieve a task by its ID, handling lazy loading with @Transactional
    @Override
    @Transactional
    public TaskDto getTaskById(Long taskId) {
        Optional<Task> optionalTask = taskRepository.findById(taskId);
        return optionalTask.map(Task::getTaskDto).orElse(null); // Return DTO if found, otherwise null
    }

    // Update an existing task and return the updated TaskDto, handle task-user
    // association
    @Override
    @Transactional
    public TaskDto updateTask(Long taskId, TaskDto taskDto) {
        Optional<Task> optionalTask = taskRepository.findById(taskId);
        Optional<User> optionalUser = userRepository.findById(taskDto.getEmployeeId());
        if (optionalTask.isPresent() && optionalUser.isPresent()) {
            Task existingTask = optionalTask.get();
            existingTask.setTitle(taskDto.getTitle());
            existingTask.setDescription(taskDto.getDescription());
            existingTask.setDueDate(taskDto.getDueDate());
            existingTask.setPriority(taskDto.getPriority());
            existingTask.setUser(optionalUser.get()); // Reassign employee to task
            existingTask.setTaskStatus(mapStringToTaskStatus(String.valueOf(taskDto.getTaskStatus()))); // Update task
                                                                                                        // status
            return taskRepository.save(existingTask).getTaskDto(); // Save and return the updated task DTO
        }
        return null;
    }

    // Helper method to map string status to TaskStatus enum
    private TaskStatus mapStringToTaskStatus(String status) {
        return switch (status.toUpperCase()) {
            case "PENDING" -> TaskStatus.PENDING;
            case "INPROGRESS" -> TaskStatus.INPROGRESS;
            case "COMPLETED" -> TaskStatus.COMPLETED;
            case "POSTPONED" -> TaskStatus.POSTPONED;
            default -> TaskStatus.CANCELLED; // Default to CANCELLED if status is unknown
        };
    }

    // Search tasks by title, paginated
    @Override
    public Page<TaskDto> searchTaskByTitle(String title, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("dueDate").descending());
        Page<Task> taskPage = taskRepository.findAllByTitleContainingIgnoreCaseWithUser(title, pageRequest);
        List<TaskDto> taskDtos = taskPage.getContent().stream()
                .map(Task::getTaskDto)
                .collect(Collectors.toList());
        return new PageImpl<>(taskDtos, pageRequest, taskPage.getTotalElements());
    }

    // Create a comment for a task and return the created CommentDto
    @Override
    public CommentDto createComment(Long taskId, String content) {
        Optional<Task> optionalTask = taskRepository.findById(taskId);
        User user = jwtUtil.getLoggedInUser(); // Get logged-in user from JWT
        if (optionalTask.isPresent() && user != null) {
            Comment comment = new Comment();
            comment.setCreatedAt(new java.sql.Date(new java.util.Date().getTime()));
            comment.setContent(content);
            comment.setUser(user);
            comment.setTask(optionalTask.get());

            // Set postedBy field based on user's role
            if (user.getUserRole().name().equals("ADMIN")) {
                comment.setPostedBy("admin");
            } else {
                comment.setPostedBy(user.getName());
            }

            return commentRepository.save(comment).getCommentDto(); // Save and return CommentDto
        }
        throw new EntityNotFoundException("User or Task not found");
    }

    // Retrieve comments for a task, paginated
    @Override
    public Page<CommentDto> getCommentsByTaskId(Long taskId, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return commentRepository.findCommentDtosByTaskId(taskId, pageRequest);
    }
}
