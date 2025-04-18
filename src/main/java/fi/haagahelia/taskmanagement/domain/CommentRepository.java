package fi.haagahelia.taskmanagement.domain;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import fi.haagahelia.taskmanagement.domain.dto.CommentDto;

/**
 * Repository interface for Comment entity with custom DTO projections.
 */
@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {

        /**
         * Retrieves paginated CommentDto entries for a given task ID.
         * Includes logic to display 'admin' or user's name.
         *
         * @param taskId   the task ID to filter comments
         * @param pageable pagination details
         * @return page of CommentDto objects
         */
        @Query("SELECT new fi.haagahelia.taskmanagement.domain.dto.CommentDto(" +
                        "c.id, c.content, c.createdAt, t.id, u.id, " +
                        "CASE WHEN u.userRole = 'ADMIN' THEN 'admin' ELSE u.name END) " +
                        "FROM Comment c JOIN c.task t JOIN c.user u " +
                        "WHERE t.id = :taskId")
        Page<CommentDto> findCommentDtosByTaskId(@Param("taskId") Long taskId, Pageable pageable);

        /**
         * Retrieves a single CommentDto by its ID.
         * Useful for displaying individual comment details.
         *
         * @param commentId the ID of the comment
         * @return CommentDto for the given ID
         */
        @Query("SELECT new fi.haagahelia.taskmanagement.domain.dto.CommentDto(" +
                        "c.id, c.content, c.createdAt, t.id, u.id, " +
                        "CASE WHEN u.userRole = 'ADMIN' THEN 'admin' ELSE u.name END) " +
                        "FROM Comment c JOIN c.task t JOIN c.user u " +
                        "WHERE c.id = :commentId")
        CommentDto findCommentDtoById(@Param("commentId") Long commentId);
}
