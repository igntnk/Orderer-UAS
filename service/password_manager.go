package service

import (
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const cost = 20

type passwordManager struct{}

type PasswordManager interface {
	HashPassword(password string) (string, string, error)
	ComparePassword(password string, hash string, salt string) error
}

func NewPasswordManager() PasswordManager {
	return &passwordManager{}
}

func (passwordManager) HashPassword(password string) (string, string, error) {
	saltUuid, err := uuid.NewUUID()
	if err != nil {
		return "", "", err
	}
	salt := saltUuid.String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), cost)
	if err != nil {
		return "", "", err
	}

	return salt, string(hashedPassword), nil
}

func (passwordManager) ComparePassword(password string, hash string, salt string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+salt))
}
