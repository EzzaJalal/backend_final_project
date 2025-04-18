package fi.haagahelia.taskmanagement.domain.dto;

import java.sql.Date;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CommentDto {

    // Unique identifier for the comment
    private Long id;

    // The actual comment content, must not be blank
    @NotBlank(message = "Content is required")
    private String content;

    // Date the comment was created
    private Date createdAt;

    // ID of the task to which this comment belongs
    private Long taskId;

    // ID of the user who posted the comment
    private Long userId;

    // Either 'admin' or the name of the employee who posted the comment
    private String postedBy;

    // Constructor used for projecting data in custom queries
    public CommentDto(Long id, String content, Date createdAt, Long taskId, Long userId, String postedBy) {
        this.id = id;
        this.content = content;
        this.createdAt = createdAt;
        this.taskId = taskId;
        this.userId = userId;
        this.postedBy = postedBy;
    }
}
