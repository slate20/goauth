# GoAuth

GoAuth is a flexible and secure authentication module for Go applications, providing features such as user registration, login, password reset via email or security questions, and route protection.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Setting Up Your Database](#setting-up-your-database)
- [Initializing GoAuth](#initializing-goauth)
- [Managing JWT Secret](#managing-jwt-secret)
- [User Registration and Login](#user-registration-and-login)
- [Password Reset Options](#password-reset-options)
- [Protecting Routes with Authentication](#protecting-routes-with-authentication)
- [Logging Out Users](#logging-out-users)
- [Best Practices and Security Considerations](#best-practices-and-security-considerations)

## Prerequisites

- Go 1.22 or later
- A SQL database (e.g., MySQL, PostgreSQL, SQLite)
- Basic understanding of Go and web development

## Installation

To install GoAuth, run the following command in your project directory:

```bash
go get github.com/slate20/goauth
```

## Setting Up Your Database

Create the necessary tables in your database:

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) NOT NULL,
    expiration TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE security_questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    question VARCHAR(255) NOT NULL,
    answer_hash VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Initializing GoAuth

In your main application file:

```go
package main

import (
    "database/sql"
    "log"
    "time"
    "os"

    "github.com/slate20/goauth"
    _ "github.com/go-sql-driver/mysql" // Or your preferred database driver
)

var auth *goauth.AuthService

func main() {
    // Set up database connection
    db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Get JWT secret from environment variable or generate a new one
    jwtSecret := os.Getenv("JWT_SECRET")

    // Initialize AuthService
    auth, err = goauth.NewAuthService(db, jwtSecret, 24*time.Hour, 1*time.Hour)
    if err != nil {
        log.Fatal(err)
    }

    // ... rest of your application setup
}
```
### Notes on JWT Secret Initialization:

1. If `jwtSecret` is an empty string (i.e., the `JWT_SECRET` environment variable is not set), GoAuth will automatically generate a new random secret.

2. When a new secret is generated, it will be printed to the console. You should save this secret securely and use it for subsequent runs of your application by setting it as an environment variable.

3. To explicitly generate a new secret on initialization, you can pass an empty string:

   ```go
   auth, err = goauth.NewAuthService(db, "", 24*time.Hour, 1*time.Hour)
   ```

4. In a production environment, it's recommended to always provide a pre-generated secret through the environment variable to ensure consistency across application restarts and multiple instances.

5. You can rotate the JWT secret at any time using the `CycleJWTSecret()` method, as described in the [Managing JWT Secret](#managing-jwt-secret) section below.

Remember, the security of your JWT tokens (and thus, your entire authentication system) depends on keeping this secret secure. Treat it with the same level of security as you would database credentials or other sensitive information.

## Managing JWT Secret

GoAuth provides methods to manage the JWT secret used for token signing and verification:

### Setting a New JWT Secret

You can set a new JWT secret at any time using the `SetJWTSecret` method:

```go
err := auth.SetJWTSecret(newSecret)
if err != nil {
    log.Printf("Error setting new JWT secret: %v", err)
}
```

If you pass an empty string, a new random secret will be generated and printed to the console.

### Cycling the JWT Secret

To generate a new random JWT secret, you can use the `CycleJWTSecret` method:

```go
newSecret, err := auth.CycleJWTSecret()
if err != nil {
    log.Printf("Error cycling JWT secret: %v", err)
} else {
    log.Printf("New JWT secret generated: %s", newSecret)
    // Save this new secret securely for future use
}
```

Note: When cycling the secret, all existing tokens will become invalid. You should implement a strategy to handle this, such as:
- Gradually rolling out the new secret
- Maintaining a list of valid old secrets for a short period
- Forcing all users to log in again

## User Registration and Login

### User Registration

```go
func registerHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    email := r.FormValue("email")
    password := r.FormValue("password")

    err := auth.Register(username, email, password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    fmt.Fprintf(w, "User registered successfully")
}
```

### User Login

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    token, err := auth.Login(username, password)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Set the token in a cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    token,
        HttpOnly: true,
    })

    fmt.Fprintf(w, "Login successful")
}
```

## Password Reset Options

GoAuth currently supports two methods for password reset: email-based and security questions-based.

### Email-based Password Reset

1. Generate a reset token:

```go
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    token, err := auth.GeneratePasswordResetToken(email)
    if err != nil {
        http.Error(w, "Error generating reset token", http.StatusInternalServerError)
        return
    }
    // Send this token to the user's email
    // ...
}
```

2. Reset the password using the token:

```go
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    newPassword := r.FormValue("new_password")
    err := auth.ResetPasswordWithToken(token, newPassword)
    if err != nil {
        http.Error(w, "Error resetting password", http.StatusBadRequest)
        return
    }
    fmt.Fprintf(w, "Password reset successfully")
}
```

### Security Questions-based Password Reset

1. Set security questions for a user:

```go
func setSecurityQuestionsHandler(w http.ResponseWriter, r *http.Request) {
    userID := getCurrentUserID(r) // You'll need to implement this function
    questions := r.Form["questions"]
    answers := r.Form["answers"]
    
    err := auth.SetSecurityQuestions(userID, questions, answers)
    if err != nil {
        http.Error(w, "Error setting security questions", http.StatusInternalServerError)
        return
    }
    fmt.Fprintf(w, "Security questions set successfully")
}
```

2. Get security questions for a user:

```go
func getSecurityQuestionsHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    questions, err := auth.GetSecurityQuestions(username)
    if err != nil {
        http.Error(w, "Error retrieving security questions", http.StatusBadRequest)
        return
    }
    // Display questions to the user
    // ...
}
```

3. Reset password using security questions:

```go
func resetPasswordWithQuestionsHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    answers := r.Form["answers"]
    newPassword := r.FormValue("new_password")
    
    err := auth.ResetPasswordWithSecurityAnswers(username, answers, newPassword)
    if err != nil {
        http.Error(w, "Error resetting password", http.StatusBadRequest)
        return
    }
    fmt.Fprintf(w, "Password reset successfully")
}
```

## Protecting Routes with Authentication

Create a middleware to protect routes:

```go
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("auth_token")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        token, err := auth.ValidateToken(cookie.Value)
        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Token is valid, call the next handler
        next.ServeHTTP(w, r)
    }
}

// Usage
http.HandleFunc("/protected", authMiddleware(protectedHandler))
```

## Logging Out Users

To log out a user, simply clear the auth token cookie:

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    "",
        HttpOnly: true,
        MaxAge:   -1,
    })
    fmt.Fprintf(w, "Logged out successfully")
}
```

## Best Practices and Security Considerations

1. Always use HTTPS in production to encrypt data in transit.
2. Implement rate limiting for login attempts, password resets, and security question attempts to prevent brute-force attacks.
3. Use strong, unique JWT secrets and rotate them periodically.
4. Encourage users to choose strong passwords and unique security questions/answers.
5. Implement proper error handling and logging in your application.
6. Consider adding additional security features like two-factor authentication.
7. Regularly update the GoAuth module and other dependencies.
8. Implement a secure password reset flow, preferably using email-based resets when possible.
9. Use prepared statements (already implemented in GoAuth) to prevent SQL injection attacks.
10. Consider implementing account lockout after a certain number of failed login or reset attempts.

By following this guide and best practices, you should now have a robust authentication system integrated into your Go application using GoAuth. Remember to adapt the code examples to fit your specific application structure and requirements.