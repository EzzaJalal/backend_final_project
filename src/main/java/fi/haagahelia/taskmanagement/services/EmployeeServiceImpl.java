package fi.haagahelia.taskmanagement.services;

import fi.haagahelia.taskmanagement.domain.Comment;
import fi.haagahelia.taskmanagement.domain.CommentRepository;
import fi.haagahelia.taskmanagement.domain.Task;
import fi.haagahelia.taskmanagement.domain.TaskRepository;
import fi.haagahelia.taskmanagement.domain.TaskStatus;
import fi.haagahelia.taskmanagement.domain.User;
import fi.haagahelia.taskmanagement.domain.UserRole;
import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import fi.haagahelia.taskmanagement.utils.JwtUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Implementation of EmployeeService. Provides methods for managing tasks
 * and comments specific to the logged-in employee, including task updates
 * and retrieval, as well as comment creation and retrieval.
 */
@Service
@RequiredArgsConstructor
public class EmployeeServiceImpl implements EmployeeService {

    private final TaskRepository taskRepository;
    private final JwtUtil jwtUtil;
    private final CommentRepository commentRepository;

    @Override
    public Page<TaskDto> getTasksByUserId(int page, int size) {
        User user = jwtUtil.getLoggedInUser();
        if (user != null) {
            PageRequest pageRequest = PageRequest.of(page, size);
            return taskRepository.findTaskDtosByUserId(user.getId(), pageRequest);
        }
        throw new EntityNotFoundException("User not found");
    }

    @Override
    @Transactional
    public TaskDto updateTask(Long taskId, String status) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new EntityNotFoundException("Task not found with id: " + taskId));
        User user = jwtUtil.getLoggedInUser();
        if (user.getUserRole() != UserRole.ADMIN && !task.getUser().getId().equals(user.getId())) {
            throw new EntityNotFoundException("Task does not belong to user");
        }
        task.setTaskStatus(TaskStatus.valueOf(status.trim().toUpperCase()));
        taskRepository.save(task);
        return taskRepository.findTaskDtoById(taskId);
    }

    @Override
    @Transactional
    public TaskDto updateTask(Long taskId, TaskDto taskDto) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new EntityNotFoundException("Task not found with id: " + taskId));
        User user = jwtUtil.getLoggedInUser();
        if (user.getUserRole() != UserRole.ADMIN && !task.getUser().getId().equals(user.getId())) {
            throw new EntityNotFoundException("Task does not belong to user");
        }
        task.setTitle(taskDto.getTitle());
        task.setDescription(taskDto.getDescription());
        task.setDueDate(taskDto.getDueDate());
        task.setPriority(taskDto.getPriority());
        task.setTaskStatus(taskDto.getTaskStatus());
        taskRepository.save(task);
        return taskRepository.findTaskDtoById(taskId);
    }

    @Override
    @Transactional
    public CommentDto createComment(Long taskId, String content) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new EntityNotFoundException("Task not found with id: " + taskId));
        User user = jwtUtil.getLoggedInUser();
        if (user == null) {
            throw new EntityNotFoundException("User not found");
        }
        if (user.getUserRole() != UserRole.ADMIN && !task.getUser().getId().equals(user.getId())) {
            throw new EntityNotFoundException("Task does not belong to user");
        }
        Comment comment = new Comment();
        comment.setCreatedAt(new java.sql.Date(new java.util.Date().getTime()));
        comment.setContent(content);
        comment.setUser(user);
        comment.setTask(task);
        if (user.getUserRole() == UserRole.ADMIN) {
            comment.setPostedBy("admin");
        } else {
            comment.setPostedBy(user.getName());
        }
        Comment savedComment = commentRepository.save(comment);
        CommentDto dto = commentRepository.findCommentDtoById(savedComment.getId());
        if (dto == null) {
            throw new EntityNotFoundException("Created comment not found");
        }
        return dto;
    }

    @Override
    public Page<CommentDto> getCommentsByTaskId(Long taskId, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return commentRepository.findCommentDtosByTaskId(taskId, pageRequest);
    }

    @Override
    @Transactional
    public TaskDto getTaskById(Long taskId) {
        User user = jwtUtil.getLoggedInUser();
        if (user == null) {
            throw new EntityNotFoundException("User not found");
        }
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new EntityNotFoundException("Task not found with id: " + taskId));
        if (user.getUserRole() != UserRole.ADMIN && !task.getUser().getId().equals(user.getId())) {
            throw new EntityNotFoundException("Task does not belong to user");
        }
        return taskRepository.findTaskDtoById(taskId);
    }
}