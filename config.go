package main

import (
	"crypto/tls"
	"io/ioutil"
	"os"
)

var masterPassword []byte

type configuration struct {
	Database struct {
		Source       string `json:"source"`
		PasswordFile string `json:"passwordFile"`
		DeleteOnBoot bool   `json:"deleteOnBoot"`
	} `json:"database"`

	Environment string `json:"environment"`

	Server struct {
		Listen      string   `json:"listen"`
		BaseUrl     string   `json:"baseUrl"`
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"privateKey"`
		Ciphers     []string `json:"ciphers"`
	} `json:"server"`

	Session struct {
		CookieName string `json:"cookieName"`
		Lifetime   string `json:"lifetime"`
		Secure     bool   `json:"secure"`
	} `json:"session"`
}

func (c *configuration) Password() []byte {
	if masterPassword == nil {
		file := c.Database.PasswordFile

		password, err := ioutil.ReadFile(file)
		if err != nil {
			panic("Could not read password file: " + err.Error())
		}

		if len(password) == 0 {
			panic("Password file '" + file + "' was empty.")
		}

		masterPassword = []byte(password)

		if c.Database.DeleteOnBoot {
			err := os.Remove(file)
			if err != nil {
				panic("Could not delete password file: " + err.Error())
			}
		}
	}

	return masterPassword
}

func (c *configuration) CipherSuites() []uint16 {
	ciphers := make([]uint16, 0)

	for _, cipher := range c.Server.Ciphers {
		var c uint16

		switch cipher {
		case "TLS_RSA_WITH_RC4_128_SHA":
			c = tls.TLS_RSA_WITH_RC4_128_SHA
		case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
			c = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
		case "TLS_RSA_WITH_AES_128_CBC_SHA":
			c = tls.TLS_RSA_WITH_AES_128_CBC_SHA
		case "TLS_RSA_WITH_AES_256_CBC_SHA":
			c = tls.TLS_RSA_WITH_AES_256_CBC_SHA
		case "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":
			c = tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
		case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
			c = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
			c = tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		case "TLS_ECDHE_RSA_WITH_RC4_128_SHA":
			c = tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA
		case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
			c = tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
			c = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
			c = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
			c = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
			c = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
			c = tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			c = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		case "TLS_FALLBACK_SCSV":
			c = tls.TLS_FALLBACK_SCSV
		default:
			panic("Unknown cipher '" + cipher + "' configured.")
		}

		ciphers = append(ciphers, c)
	}

	return ciphers
}
