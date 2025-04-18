package fi.haagahelia.taskmanagement.utils;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender; // Mail sender dependency to send emails
    private final TemplateEngine templateEngine; // Thymeleaf template engine for HTML email generation

    // Constructor for dependency injection of mailSender and templateEngine
    public EmailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    /**
     * Sends a plain text email.
     * 
     * @param to      Recipient email address
     * @param subject Subject of the email
     * @param body    Body content of the email
     */
    public void sendEmail(String to, String subject, String body) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(to); // Set recipient
            helper.setSubject(subject); // Set subject
            helper.setText(body, false); // Plain text email
            mailSender.send(message); // Send the email
            logger.debug("Plain text email sent to: {}, subject: {}, body: {}", to, subject, body);
        } catch (MessagingException e) {
            logger.error("Failed to send plain text email to: {}, subject: {}, body: {}", to, subject, body, e);
            throw new RuntimeException("Failed to send plain text email", e);
        }
    }

    /**
     * Sends an HTML email using a Thymeleaf template.
     * 
     * @param to           Recipient email address
     * @param subject      Subject of the email
     * @param templateName Name of the Thymeleaf template
     * @param context      Context containing data to be used in the template
     */
    public void sendHtmlEmail(String to, String subject, String templateName, Context context) {
        try {
            // Render the Thymeleaf template into an HTML string
            String htmlBody = templateEngine.process(templateName, context);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(to); // Set recipient
            helper.setSubject(subject); // Set subject
            helper.setText(htmlBody, true); // HTML email
            mailSender.send(message); // Send the email
            logger.debug("HTML email sent to: {}, subject: {}, template: {}", to, subject, templateName);
        } catch (MessagingException e) {
            logger.error("Failed to send HTML email to: {}, subject: {}, template: {}", to, subject, templateName, e);
            throw new RuntimeException("Failed to send HTML email", e);
        }
    }
}
