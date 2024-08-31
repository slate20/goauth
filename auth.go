package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

type AuthService struct {
	users     map[string]User
	jwtSecret []byte
}

// Generate a random key of the specified length
func generateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func NewAuthService() (*AuthService, error) {
	// Check for environment variable first
	secretKey := os.Getenv("AUTH_SECRET_KEY")
	var jwtSecret []byte

	if secretKey == "" {
		// If not set, generate a random key
		var err error
		jwtSecret, err = generateRandomKey(32) // 256-bit key
		if err != nil {
			return nil, err
		}
		// Save the key in the environment variable
		encodedKey := base64.StdEncoding.EncodeToString(jwtSecret)
		os.Setenv("AUTH_SECRET_KEY", encodedKey)
		println("Generated new secret key:", encodedKey)
	} else {
		// If set, decode the key
		var err error
		jwtSecret, err = base64.StdEncoding.DecodeString(secretKey)
		if err != nil {
			return nil, errors.New("invalid AUTH_SECRET_KEY format")
		}
	}

	return &AuthService{
		users:     make(map[string]User),
		jwtSecret: jwtSecret,
	}, nil
}

func (s *AuthService) Register(username, email, password string) error {
	if _, exists := s.users[username]; exists {
		return errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := User{
		ID:       len(s.users) + 1,
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
	}

	s.users[username] = user
	return nil
}

func (s *AuthService) Login(username, password string) (string, error) {
	user, exists := s.users[username]
	if !exists {
		return "", errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("invalid password")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
}
