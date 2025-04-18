package fi.haagahelia.taskmanagement.web;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;

import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;
import fi.haagahelia.taskmanagement.services.AdminService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RequiredArgsConstructor
@RequestMapping("/api/admin")
@CrossOrigin("*")
@Controller
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);
    private final AdminService adminService;

    /**
     * Handle Access Denied exceptions
     */
    @ExceptionHandler(AccessDeniedException.class)
    public String handleAccessDeniedException(AccessDeniedException ex, Model model) {
        logger.error("Access denied: {}", ex.getMessage());
        model.addAttribute("error",
                "You don't have permission to access this page. Only administrators can access admin features.");
        return "redirect:/api/auth/access-denied";
    }

    /**
     * REST API Endpoints
     */

    @GetMapping(value = "/users", produces = "application/json")
    @ResponseBody
    public ResponseEntity<List<UserDto>> getUsers() {
        return ResponseEntity.ok(adminService.getUsers());
    }

    @PostMapping(value = "/user", produces = "application/json")
    @ResponseBody
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createUser(userDto));
    }

    @DeleteMapping(value = "/user/{userId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        adminService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/task", produces = "application/json")
    @ResponseBody
    public ResponseEntity<TaskDto> createTask(@RequestBody TaskDto taskDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createTask(taskDto));
    }

    @PutMapping(value = "/task/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<TaskDto> updateTask(@PathVariable Long taskId, @RequestBody TaskDto taskDto) {
        TaskDto updatedTask = adminService.updateTask(taskId, taskDto);
        if (updatedTask == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(updatedTask);
    }

    @DeleteMapping(value = "/task/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Void> deleteTask(@PathVariable Long taskId) {
        adminService.deleteTask(taskId);
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/task/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<TaskDto> getTaskById(@PathVariable Long taskId) {
        TaskDto taskDto = adminService.getTaskById(taskId);
        if (taskDto == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(taskDto);
    }

    @GetMapping(value = "/tasks", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<TaskDto>> getAllTasks(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(adminService.getAllTasks(page, size));
    }

    @GetMapping(value = "/tasks/search", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<TaskDto>> searchTasksByTitle(
            @RequestParam String title,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(adminService.searchTaskByTitle(title, page, size));
    }

    @GetMapping(value = "/task/search/{title}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<TaskDto>> redirectSearchTasks(
            @PathVariable String title,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        logger.info("Redirecting /api/admin/task/search/{} to /api/admin/tasks/search?title={}", title, title);
        return ResponseEntity.ok(adminService.searchTaskByTitle(title, page, size));
    }

    @PostMapping(value = "/task/{taskId}/comment", produces = "application/json")
    @ResponseBody
    public ResponseEntity<CommentDto> addComment(
            @PathVariable Long taskId,
            @RequestParam String content) {
        return ResponseEntity.status(HttpStatus.CREATED).body(adminService.createComment(taskId, content));
    }

    // New mapping for POST /api/admin/task/comment/{taskId}
    @PostMapping(value = "/task/comment/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<CommentDto> addCommentAlternate(
            @PathVariable Long taskId,
            @RequestParam String content) {
        logger.debug("Received POST /api/admin/task/comment/{} with content: {}", taskId, content);
        return addComment(taskId, content);
    }

    @GetMapping(value = "/task/{taskId}/comments", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<CommentDto>> getComments(
            @PathVariable Long taskId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(adminService.getCommentsByTaskId(taskId, page, size));
    }

    @GetMapping(value = "/comments/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<CommentDto>> getCommentsByTaskId(
            @PathVariable Long taskId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(adminService.getCommentsByTaskId(taskId, page, size));
    }

    /**
     * Thymeleaf Views
     */

    @GetMapping("/users-form")
    public String showUsersForm(Model model) {
        List<UserDto> users = adminService.getUsers();
        model.addAttribute("users", users);
        return "admin-users";
    }

    @GetMapping("/create-user-form")
    public String showCreateUserForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        return "create-user";
    }

    @PostMapping("/create-user-form")
    public String createUserForm(@ModelAttribute UserDto userDto, Model model) {
        try {
            adminService.createUser(userDto);
            model.addAttribute("success", "User created successfully.");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to create user: " + e.getMessage());
        }
        return "create-user";
    }

    @GetMapping("/tasks-form")
    public String showTasksForm(@RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Model model) {
        Page<TaskDto> tasks = adminService.getAllTasks(page, size);
        model.addAttribute("tasks", tasks.getContent());
        model.addAttribute("currentPage", tasks.getNumber());
        model.addAttribute("totalPages", tasks.getTotalPages());
        return "admin-tasks";
    }

    @GetMapping("/task-details/{taskId}")
    public String showTaskDetails(@PathVariable Long taskId, Model model) {
        TaskDto taskDto = adminService.getTaskById(taskId);
        if (taskDto == null) {
            model.addAttribute("error", "Task not found.");
            return "error";
        }
        model.addAttribute("task", taskDto);
        Page<CommentDto> comments = adminService.getCommentsByTaskId(taskId, 0, 10);
        model.addAttribute("comments", comments.getContent());
        return "task-details";
    }

    @GetMapping("/create-task-form")
    public String showCreateTaskForm(Model model, @RequestParam(required = false) Long employeeId) {
        TaskDto taskDto = new TaskDto();
        if (employeeId != null) {
            taskDto.setEmployeeId(employeeId);
        }
        model.addAttribute("taskDto", taskDto);
        model.addAttribute("employees", adminService.getUsers());
        return "create-task";
    }

    @PostMapping("/create-task-form")
    public String createTaskForm(@ModelAttribute TaskDto taskDto, Model model) {
        try {
            adminService.createTask(taskDto);
            model.addAttribute("success", "Task created successfully.");
            model.addAttribute("employees", adminService.getUsers());
        } catch (Exception e) {
            model.addAttribute("error", "Failed to create task: " + e.getMessage());
            model.addAttribute("employees", adminService.getUsers());
        }
        return "create-task";
    }

    @GetMapping("/edit-task-form/{taskId}")
    public String showEditTaskForm(@PathVariable Long taskId, Model model) {
        TaskDto taskDto = adminService.getTaskById(taskId);
        if (taskDto == null) {
            model.addAttribute("error", "Task not found.");
            return "error";
        }
        model.addAttribute("taskDto", taskDto);
        model.addAttribute("employees", adminService.getUsers());
        return "edit-task";
    }

    @PostMapping("/edit-task-form/{taskId}")
    public String editTaskForm(@PathVariable Long taskId, @ModelAttribute TaskDto taskDto, Model model) {
        try {
            taskDto.setId(taskId);
            TaskDto updatedTask = adminService.updateTask(taskId, taskDto);
            if (updatedTask == null) {
                model.addAttribute("error", "Task not found.");
                return "error";
            }
            model.addAttribute("success", "Task updated successfully.");
            model.addAttribute("taskDto", updatedTask);
            model.addAttribute("employees", adminService.getUsers());
        } catch (Exception e) {
            model.addAttribute("error", "Failed to update task: " + e.getMessage());
            model.addAttribute("employees", adminService.getUsers());
        }
        return "edit-task";
    }

    @GetMapping("/search-tasks-form")
    public String showSearchTasksForm(@RequestParam(required = false) String title,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Model model) {
        if (title != null && !title.isEmpty()) {
            Page<TaskDto> tasks = adminService.searchTaskByTitle(title, page, size);
            model.addAttribute("tasks", tasks.getContent());
            model.addAttribute("currentPage", tasks.getNumber());
            model.addAttribute("totalPages", tasks.getTotalPages());
            model.addAttribute("searchQuery", title);
        }
        return "search-tasks";
    }

    @GetMapping("/add-comment-form/{taskId}")
    public String showAddCommentForm(@PathVariable Long taskId, Model model) {
        TaskDto taskDto = adminService.getTaskById(taskId);
        if (taskDto == null) {
            model.addAttribute("error", "Task not found.");
            return "error";
        }
        model.addAttribute("task", taskDto);
        model.addAttribute("taskId", taskId);
        model.addAttribute("taskTitle", taskDto.getTitle());
        Page<CommentDto> comments = adminService.getCommentsByTaskId(taskId, 0, 10);
        model.addAttribute("comments", comments.getContent());
        return "admin-add-comment";
    }

    @PostMapping("/add-comment-form/{taskId}")
    public String addCommentForm(@PathVariable Long taskId, @RequestParam String content, Model model) {
        try {
            adminService.createComment(taskId, content);
            return "redirect:/api/admin/task-details/" + taskId;
        } catch (Exception e) {
            TaskDto taskDto = adminService.getTaskById(taskId);
            model.addAttribute("task", taskDto);
            model.addAttribute("taskId", taskId);
            model.addAttribute("taskTitle", taskDto != null ? taskDto.getTitle() : "Unknown");
            model.addAttribute("error", "Failed to add comment: " + e.getMessage());
            return "admin-add-comment";
        }
    }

    @PostMapping("/task/{taskId}/comment")
    public String addCommentFromTaskDetails(@PathVariable Long taskId, @RequestParam String content, Model model) {
        try {
            adminService.createComment(taskId, content);
            model.addAttribute("success", "Comment added successfully");
        } catch (Exception e) {
            logger.error("Error adding comment to task {}: {}", taskId, e.getMessage());
            model.addAttribute("error", "Failed to add comment: " + e.getMessage());
        }
        return "redirect:/api/admin/task-details/" + taskId;
    }

    @PostMapping("/task/{taskId}")
    public String deleteTask(@PathVariable Long taskId, @RequestParam(required = false) String _method, Model model) {
        if (_method != null && _method.equalsIgnoreCase("DELETE")) {
            try {
                adminService.deleteTask(taskId);
                model.addAttribute("success", "Task deleted successfully");
            } catch (Exception e) {
                logger.error("Error deleting task {}: {}", taskId, e.getMessage());
                model.addAttribute("error", "Failed to delete task: " + e.getMessage());
            }
        }
        return "redirect:/api/admin/tasks-form";
    }

    @PostMapping("/user/{userId}")
    public String deleteUser(@PathVariable Long userId, @RequestParam(required = false) String _method, Model model) {
        if (_method != null && _method.equalsIgnoreCase("DELETE")) {
            try {
                adminService.deleteUser(userId);
                model.addAttribute("success", "User deleted successfully");
            } catch (Exception e) {
                logger.error("Error deleting user {}: {}", userId, e.getMessage());
                model.addAttribute("error", "Failed to delete user: " + e.getMessage());
            }
        }
        return "redirect:/api/admin/users-form";
    }
}