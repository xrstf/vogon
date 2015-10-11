package main

import (
	"github.com/xrstf/boxer"

	"golang.org/x/crypto/bcrypt"
)

func Encrypt(input []byte) ([]byte, error) {
	return boxer.NewDefaultBoxer().Encrypt(input, config.Password())
}

func Decrypt(input []byte) ([]byte, error) {
	return boxer.NewDefaultBoxer().Decrypt(input, config.Password())
}

func HashBcrypt(str string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(str), 10)
	if err != nil {
		panic(err)
	}

	return hash
}

func CompareBcrypt(hash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
