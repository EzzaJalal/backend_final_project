📝 Task Management System
A full-stack Task Management System built using Spring Boot, Maven, JWT Authentication, Thymeleaf, Bootstrap, and JavaScript.

📌 Features
This project demonstrates a fully functional task management system with two distinct user roles: Admin and Employee.

🔐 Authentication

User Sign Up

Login

Password Reset

Email Verification

👑 Admin Capabilities
Create, read, update, and delete tasks

Assign tasks to employees

Add and remove employees

Post and view comments on tasks

Search tasks by title

View all users and task data

👤 Employee Capabilities
View assigned tasks by user ID

Update task status

Post comments for assigned tasks

View comments for their tasks

🚀 Technologies Used
Backend: Spring Boot, Spring Security, JWT, Maven

Frontend: Thymeleaf, Bootstrap, JavaScript

Database: (You can add this – e.g., PostgreSQL/MariaDB)

Email Service: (You can mention JavaMailSender or service used)

🔗 API Endpoints
🔒 Authentication
Sign Up (POST):
http://localhost:8080/api/auth/signup

Login (POST):
http://localhost:8080/api/auth/login

Verify Email (GET):
http://localhost:8080/api/auth/verify-email?token=

Forgot Password (POST):
http://localhost:8080/api/auth/forgot-password?email=john.doe@example.com

Reset Password (POST):
http://localhost:8080/api/auth/reset-password?token=&newPassword=newpass123

👑 Admin APIs
Get All Users (GET):
http://localhost:8080/api/admin/users

Create User (POST):
http://localhost:8080/api/admin/user

Delete User (DELETE):
http://localhost:8080/api/admin/user/{userId}

Create Task (POST):
http://localhost:8080/api/admin/task

Get All Tasks (GET):
http://localhost:8080/api/admin/tasks?page=0&size=10

Delete Task (DELETE):
http://localhost:8080/api/admin/task/{taskId}

Get Task by ID (GET):
http://localhost:8080/api/admin/task/{taskId}

Update Task (PUT):
http://localhost:8080/api/admin/task/{taskId}

Search Tasks by Title (GET):
http://localhost:8080/api/admin/task/search/{searchTerm}?page=0&size=10

Create Comment (POST):
http://localhost:8080/api/admin/task/comment/{taskId}?content=Great progress!

Get Comments by Task ID (GET):
http://localhost:8080/api/admin/comments/{taskId}?page=0&size=10

👤 Employee APIs
Get Tasks by User ID (GET):
http://localhost:8080/api/employee/tasks?page=0&size=10

Update Task Status (GET):
http://localhost:8080/api/employee/task/{taskId}/COMPLETED

Update Task (PUT):
http://localhost:8080/api/employee/task/{taskId}

Create Comment (POST):
http://localhost:8080/api/employee/task/comment/{taskId}?content=Nice work!

Get Comments by Task ID (GET):
http://localhost:8080/api/employee/comments/{taskId}?page=0&size=10

📷 Screenshots
(Add any UI screenshots or diagrams here if available)

🛠️ Installation & Setup
Clone the repository
git clone https://github.com/yourusername/task-management-system.git

Navigate to the project directory
cd task-management-system

Run the project with your preferred IDE or with Maven
mvn spring-boot:run

Visit:
http://localhost:8080

📧 Contact
For any queries or feedback, feel free to contact me via [syedaezzajalal@gmail.com] or connect on LinkedIn via [https://www.linkedin.com/in/ezza-jalal-finland]
