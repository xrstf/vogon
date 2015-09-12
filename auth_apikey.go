package main

import (
	"errors"
	"net/http"
	"strings"
)

// import "crypto/subtle"

////////////////////////////////////////////////////////////////////////////////////////////////////
// authentication handler

type ApiKeyAuthentication struct{}

func (ApiKeyAuthentication) GetIdentifier() string {
	return "api_key"
}

func (ApiKeyAuthentication) GetNullContext() interface{} {
	auth := apiKeyContext{""} // prevent bcrypting the empty string (if we instead called newApiKeyContext)

	return &auth
}

func (ApiKeyAuthentication) SerializeForm(req *http.Request, oldCtx interface{}) (interface{}, error) {
	value := strings.TrimSpace(req.FormValue("auth_api_key_key"))

	if len(value) == 0 {
		if oldCtx == nil {
			return nil, errors.New("No API key given.")
		}

		return oldCtx, nil
	}

	return newApiKeyContext(value), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type apiKeyContext struct {
	// hash of the API key (we never actually store the key itself)
	Hash string `json:"hash-bcrypt"`
}

func newApiKeyContext(apiKey string) *apiKeyContext {
	return &apiKeyContext{string(HashBcrypt(apiKey))}
}
