package fi.haagahelia.taskmanagement.domain;

import java.sql.Date;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import com.fasterxml.jackson.annotation.JsonIgnore;
import fi.haagahelia.taskmanagement.domain.dto.CommentDto;
import jakarta.persistence.*;
import lombok.Data;

/**
 * Represents a comment entity linked to a specific task and user.
 * Stores content, creation date, and metadata about the commenter.
 */
@Entity
@Data
public class Comment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Text content of the comment */
    private String content;

    /** Date when the comment was created */
    private Date createdAt;

    /** Identifier for who posted the comment (e.g., user name or 'admin') */
    @Column(name = "posted_by")
    private String postedBy;

    /** The user who posted the comment */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    private User user;

    /** The task associated with the comment */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "task_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    private Task task;

    /**
     * Converts this Comment entity to a CommentDto for data transfer.
     *
     * @return a CommentDto with relevant data populated
     */
    public CommentDto getCommentDto() {
        CommentDto commentDto = new CommentDto();
        commentDto.setId(id);
        commentDto.setContent(content);
        commentDto.setCreatedAt(createdAt);
        commentDto.setTaskId(task.getId());
        commentDto.setUserId(user.getId());
        commentDto.setPostedBy(postedBy);
        return commentDto;
    }
}
