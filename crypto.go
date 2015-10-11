package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

const saltLength = 8
const nonceLength = 24
const keyLength = 32

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
	box := make([]byte, saltLength+nonceLength)
	copy(box, kdSalt[:])
	copy(box[saltLength:], nonce[:])

	box = secretbox.Seal(box, input, nonce, encryptionKey)

	return box, nil
}

func Decrypt(input []byte) ([]byte, error) {
	minLength := saltLength + nonceLength + secretbox.Overhead + 1

	if len(input) < minLength {
		return nil, errors.New(fmt.Sprintf("The ciphertext is too short (%d bytes) to be valid. It needs to be at least %d bytes.", len(input), minLength))
	}

	salt := new([saltLength]byte)
	nonce := new([nonceLength]byte)

	copy(salt[:], input[:saltLength])
	copy(nonce[:], input[saltLength:(saltLength+nonceLength)])

	encryptionKey, err := deriveKeyWithSalt(config.Password(), salt)
	if err != nil {
		return nil, err
	}

	box := input[(saltLength + nonceLength):]

	plain, success := secretbox.Open(nil, box, nonce, encryptionKey)
	if !success {
		return nil, errors.New("Decrypting failed, probably due to a wrong password.")
	}

	return plain, nil
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

func deriveKey(password []byte) (*[keyLength]byte, *[saltLength]byte, error) {
	// create the salt for key derivation
	salt := new([saltLength]byte)

	_, err := rand.Reader.Read(salt[:])
	if err != nil {
		return nil, nil, errors.New("Could not gather sufficient random data to perform encryption: " + err.Error())
	}

	key, err := deriveKeyWithSalt(password, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func deriveKeyWithSalt(password []byte, salt *[saltLength]byte) (*[keyLength]byte, error) {
	// create encryption key (32byte) from the password using PBKDF2 (RFC 2898)
	key := new([keyLength]byte)
	copy(key[:], pbkdf2.Key(password, salt[:], 8192, keyLength, sha256.New))

	return key, nil
}

func createNonce() (*[nonceLength]byte, error) {
	nonce := new([nonceLength]byte)
	now := time.Now().UnixNano()

	binary.BigEndian.PutUint64(nonce[:], uint64(now))

	_, err := rand.Reader.Read(nonce[8:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
