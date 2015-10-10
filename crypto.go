package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(input []byte) ([]byte, error) {
	// derive a new encryption key for this message
	encryptionKey, kdSalt, err := deriveKey(config.Password())
	if err != nil {
		return nil, errors.New("Could not derive encryption key from password: " + err.Error())
	}

	// create a fresh nonce
	nonce, err := createNonce()
	if err != nil {
		return nil, errors.New("Could not create nonce: " + err.Error())
	}

	// seal the data in a nacl box; the box will have the kd salt and nonce prepended
	box := make([]byte, 8+24)
	copy(box, kdSalt[:])
	copy(box[8:], nonce[:])

	box = secretbox.Seal(box, input, nonce, encryptionKey)

	return box, nil
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

func CompareBcrypt(hash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func deriveKey(password []byte) (*[32]byte, *[8]byte, error) {
	// create the salt for key derivation
	salt := new([8]byte)
	_, err := rand.Reader.Read(salt[:])
	if err != nil {
		return nil, nil, errors.New("Could not gather sufficient random data to perform encryption: " + err.Error())
	}

	// run PBKDF2 (RFC 2898)
	encryptionKey := new([32]byte)
	copy(encryptionKey[:], pbkdf2.Key(password, salt[:], 8192, 32, sha256.New))

	return encryptionKey, salt, nil
}

func createNonce() (*[24]byte, error) {
	nonce := new([24]byte)
	now := time.Now().UnixNano()

	binary.BigEndian.PutUint64(nonce[:], uint64(now))

	_, err := rand.Reader.Read(nonce[8:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
