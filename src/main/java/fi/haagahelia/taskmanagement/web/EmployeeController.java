package fi.haagahelia.taskmanagement.web;

import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import fi.haagahelia.taskmanagement.domain.dto.TaskDto;
import fi.haagahelia.taskmanagement.services.EmployeeService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@RequestMapping("/api/employee")
@CrossOrigin("*")
@RequiredArgsConstructor
@Controller
public class EmployeeController {

    private static final Logger logger = LoggerFactory.getLogger(EmployeeController.class);
    private final EmployeeService employeeService;

    /**
     * REST API Endpoints
     */

    @GetMapping(value = "/tasks", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<TaskDto>> getTasksByUserId(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(employeeService.getTasksByUserId(page, size));
    }

    @GetMapping(value = "/task/{id}/{status}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<TaskDto> updateTaskStatus(@PathVariable Long id, @PathVariable String status) {
        TaskDto updatedTaskDto = employeeService.updateTask(id, status);
        if (updatedTaskDto == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.ok(updatedTaskDto);
    }

    @PutMapping(value = "/task/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<TaskDto> updateTask(
            @PathVariable Long taskId,
            @RequestBody TaskDto taskDto) {
        TaskDto updatedTask = employeeService.updateTask(taskId, taskDto);
        if (updatedTask == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        return ResponseEntity.ok(updatedTask);
    }

    @PostMapping(value = "/task/{taskId}/comment", produces = "application/json")
    @ResponseBody
    public ResponseEntity<CommentDto> addComment(
            @PathVariable Long taskId,
            @RequestParam String content) {
        logger.debug("Received POST /api/employee/task/{}/comment with content: {}", taskId, content);
        CommentDto commentDto = employeeService.createComment(taskId, content);
        if (commentDto == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.status(HttpStatus.CREATED).body(commentDto);
    }

    // New mapping for POST /api/employee/task/comment/{taskId}
    @PostMapping(value = "/task/comment/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<CommentDto> addCommentAlternate(
            @PathVariable Long taskId,
            @RequestParam String content) {
        logger.debug("Received POST /api/employee/task/comment/{} with content: {}", taskId, content);
        return addComment(taskId, content);
    }

    @GetMapping(value = "/task/{taskId}/comments", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<CommentDto>> getComments(
            @PathVariable Long taskId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(employeeService.getCommentsByTaskId(taskId, page, size));
    }

    @GetMapping(value = "/comments/{taskId}", produces = "application/json")
    @ResponseBody
    public ResponseEntity<Page<CommentDto>> getCommentsByTaskId(
            @PathVariable Long taskId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(employeeService.getCommentsByTaskId(taskId, page, size));
    }

    /**
     * Thymeleaf Views
     */

    @GetMapping("/tasks-form")
    public String showTasksForm(@RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Model model) {
        Page<TaskDto> tasks = employeeService.getTasksByUserId(page, size);
        model.addAttribute("tasks", tasks.getContent());
        model.addAttribute("currentPage", tasks.getNumber());
        model.addAttribute("totalPages", tasks.getTotalPages());
        return "employee-tasks";
    }

    @GetMapping("/update-task-status-form/{id}")
    public String showUpdateTaskStatusForm(@PathVariable Long id, Model model) {
        try {
            TaskDto taskDto = employeeService.getTaskById(id);
            model.addAttribute("task", taskDto);
            return "update-task-status";
        } catch (Exception e) {
            model.addAttribute("error", "Task not found: " + e.getMessage());
            return "error";
        }
    }

    @PostMapping("/update-task-status-form/{id}")
    public String updateTaskStatusForm(@PathVariable Long id, @RequestParam String status, Model model,
            RedirectAttributes redirectAttributes) {
        try {
            TaskDto updatedTaskDto = employeeService.updateTask(id, status);
            if (updatedTaskDto == null) {
                model.addAttribute("error", "Failed to update task status.");
                model.addAttribute("task", employeeService.getTaskById(id));
                return "update-task-status";
            }
            redirectAttributes.addFlashAttribute("success", "Task status updated successfully.");
            return "redirect:/api/employee/tasks-form";
        } catch (Exception e) {
            model.addAttribute("error", "Failed to update task status: " + e.getMessage());
            try {
                model.addAttribute("task", employeeService.getTaskById(id));
            } catch (Exception ex) {
                redirectAttributes.addFlashAttribute("error", "Failed to update task status: " + e.getMessage());
                return "redirect:/api/employee/tasks-form";
            }
            return "update-task-status";
        }
    }

    @GetMapping("/task-details/{taskId}")
    public String showTaskDetails(@PathVariable Long taskId, Model model) {
        try {
            TaskDto taskDto = employeeService.getTaskById(taskId);
            model.addAttribute("task", taskDto);
            Page<CommentDto> comments = employeeService.getCommentsByTaskId(taskId, 0, 10);
            model.addAttribute("comments", comments.getContent());
            return "employee-task-details";
        } catch (Exception e) {
            model.addAttribute("error", "Task not found: " + e.getMessage());
            return "error";
        }
    }

    @GetMapping("/add-comment-form/{taskId}")
    public String showAddCommentForm(@PathVariable Long taskId, Model model) {
        try {
            TaskDto taskDto = employeeService.getTaskById(taskId);
            model.addAttribute("taskId", taskId);
            model.addAttribute("taskTitle", taskDto.getTitle());
            model.addAttribute("task", taskDto);
            return "add-comment";
        } catch (Exception e) {
            model.addAttribute("error", "Task not found: " + e.getMessage());
            return "error";
        }
    }

    @PostMapping("/add-comment-form/{taskId}")
    public String addCommentForm(@PathVariable Long taskId, @RequestParam String content, Model model) {
        try {
            CommentDto commentDto = employeeService.createComment(taskId, content);
            if (commentDto == null) {
                model.addAttribute("error", "Failed to add comment.");
                return "add-comment";
            }
            model.addAttribute("success", "Comment added successfully.");
            return "redirect:/api/employee/task-details/" + taskId;
        } catch (Exception e) {
            model.addAttribute("error", "Failed to add comment: " + e.getMessage());
            model.addAttribute("taskId", taskId);
            return "add-comment";
        }
    }
}