package goauth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db                   *sql.DB // Database connection
	jwtSecret            []byte  // JWT secret key
	tokenExpiration      time.Duration
	resetTokenExpiration time.Duration
	mu                   sync.RWMutex
}

func generateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func NewAuthService(db *sql.DB, jwtSecret string, tokenExpiration, resetTokenExpiration time.Duration) (*AuthService, error) {
	service := &AuthService{
		db:                   db,
		tokenExpiration:      tokenExpiration,
		resetTokenExpiration: resetTokenExpiration,
	}

	err := service.SetJWTSecret(jwtSecret)
	if err != nil {
		return nil, err
	}

	return service, nil
}

func (s *AuthService) SetJWTSecret(jwtSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var secret []byte
	var err error

	if jwtSecret == "" {
		secret, err = generateRandomKey(32) // Generate a 256-bit key
		if err != nil {
			return err
		}
		encodedSecret := base64.StdEncoding.EncodeToString(secret)
		println("Generated new JWT secret. Please save this for future use:")
		println(encodedSecret)
	} else {
		secret, err = base64.StdEncoding.DecodeString(jwtSecret)
		if err != nil {
			return errors.New("invalid JWT secret format")
		}
	}

	s.jwtSecret = secret
	return nil
}

func (s *AuthService) CycleJWTSecret() (string, error) {
	newSecret, err := generateRandomKey(32)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.jwtSecret = newSecret
	s.mu.Unlock()

	encodedSecret := base64.StdEncoding.EncodeToString(newSecret)
	return encodedSecret, nil
}

func (s *AuthService) Register(username, email, password string) error {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert the user into the database
	_, err = s.db.Exec("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
		username, email, string(hashedPassword))

	return err
}

func (s *AuthService) Login(username, password string) (string, error) {
	var user struct {
		ID           int
		PasswordHash string
	}

	// Retrieve user from the database
	err := s.db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&user.ID, &user.PasswordHash)
	if err != nil {
		return "", errors.New("user not found")
	}

	// Compare the provided password with the stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", errors.New("invalid password")
	}

	// Create a new JWT token
	s.mu.RLock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(s.jwtSecret)
	s.mu.RUnlock()

	return tokenString, err
}

func (s *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
}

// Email-based password reset
func (s *AuthService) GeneratePasswordResetToken(email string) (string, error) {
	var userID int
	err := s.db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		return "", errors.New("user not found")
	}

	token := make([]byte, 32)
	_, err = rand.Read(token)
	if err != nil {
		return "", err
	}
	resetToken := base64.URLEncoding.EncodeToString(token)

	expirationTime := time.Now().Add(s.resetTokenExpiration)
	_, err = s.db.Exec("INSERT INTO password_reset_tokens (user_id, token, expiration) VALUES (?, ?, ?)", userID, resetToken, expirationTime)
	if err != nil {
		return "", err
	}
	return resetToken, nil
}

func (s *AuthService) ValidatePasswordResetToken(token string) (int, error) {
	var userID int
	var expiration time.Time
	err := s.db.QueryRow("SELECT user_id, expiration FROM password_reset_tokens WHERE token = ?", token).Scan(&userID, &expiration)
	if err != nil {
		return 0, errors.New("invalid or expired token")
	}

	if time.Now().After(expiration) {
		return 0, errors.New("token has expired")
	}
	return userID, nil
}

func (s *AuthService) ResetPasswordWithToken(token, password string) error {
	userID, err := s.ValidatePasswordResetToken(token)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), userID)
	if err != nil {
		return err
	}

	_, err = s.db.Exec("DELETE FROM password_reset_tokens WHERE user_id = ?", userID)
	return err
}

// Security question-based password reset
func (s *AuthService) SetSecurityQuestions(userID int, questions []string, answers []string) error {
	if len(questions) != len(answers) {
		return errors.New("number of questions and answers must match")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing security questions
	_, err = tx.Exec("DELETE FROM security_questions WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	// Insert new security questions
	for i := range questions {
		hashedAndswer, err := bcrypt.GenerateFromPassword([]byte(answers[i]), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		_, err = tx.Exec("INSERT INTO security_questions (user_id, question, answer) VALUES (?, ?, ?)", userID, questions[i], string(hashedAndswer))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *AuthService) GetSecurityQuestions(username string) ([]string, error) {
	rows, err := s.db.Query("SELECT question FROM security_questions sq JOIN users u ON sq.user_id = u.id WHERE u.username = ?", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var questions []string
	for rows.Next() {
		var question string
		if err := rows.Scan(&question); err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}

	if len(questions) == 0 {
		return nil, errors.New("no security questions found")
	}

	return questions, nil
}

func (s *AuthService) ValidateSecurityAnswers(username string, answers []string) (int, error) {
	var userID int
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return 0, errors.New("user not found")
	}

	rows, err := s.db.Query("SELECT answer_hash FROM security_questions WHERE user_id = ? ORDER BY id", userID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var storedHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return 0, err
		}
		storedHashes = append(storedHashes, hash)
	}

	if len(storedHashes) != len(answers) {
		return 0, errors.New("number of answers does not match")
	}

	for i, hash := range storedHashes {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(answers[i])); err != nil {
			return 0, errors.New("incorrect answer")
		}
	}

	return userID, nil
}

func (s *AuthService) ResetPasswordWithSecurityAnswers(username string, answers []string, newPassword string) error {
	userID, err := s.ValidateSecurityAnswers(username, answers)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), userID)
	return err
}

func (s *AuthService) UpdateUserPassword(userID int, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), userID)
	return err
}
