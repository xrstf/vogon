package main

import (
	"golang.org/x/crypto/bcrypt"
)

func Encrypt(input []byte) []byte {
	return input
}

func Decrypt(input []byte) []byte {
	return input
}

func HashBcrypt(str string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(str), 10)
	if err != nil {
		panic(err)
	}

	return hash
}
