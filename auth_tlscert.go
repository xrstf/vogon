package main

import "strings"
import "errors"
import "net/http"

// import "crypto/subtle"

////////////////////////////////////////////////////////////////////////////////////////////////////
// authentication handler

type TlsCertAuthentication struct{}

func (TlsCertAuthentication) GetIdentifier() string {
	return "tls_cert"
}

func (TlsCertAuthentication) GetNullContext() interface{} {
	return newTlsCertContext("", 0)
}

func (TlsCertAuthentication) SerializeForm(req *http.Request, oldCtx interface{}) (interface{}, error) {
	value := strings.TrimSpace(req.FormValue("auth_api_key_key"))

	if len(value) == 0 {
		if oldCtx == nil {
			return nil, errors.New("No API key given.")
		}

		return oldCtx, nil
	}

	return newTlsCertContext("", 42), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type tlsCertContext struct {
	Issuer string `json:"issuer"`
	Serial int    `json:"serial"`
}

func newTlsCertContext(issuer string, serial int) *tlsCertContext {
	return &tlsCertContext{issuer, serial}
}
