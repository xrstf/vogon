package main

import (
	"errors"
	"net/http"
	"strings"
)

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

type apiKeyAccessContext struct {
	Error string `json:"error"`
}

func (ApiKeyAuthentication) CheckAccess(request *http.Request, context interface{}) (bool, interface{}) {
	ctx, okay := context.(*apiKeyContext)
	if !okay {
		return false, apiKeyAccessContext{"Invalid context given. This should never happen."}
	}

	providedKey := request.FormValue("raziel_key")
	if len(providedKey) == 0 {
		providedKey = request.Header.Get("X-Raziel-Key")

		if len(providedKey) == 0 {
			return false, apiKeyAccessContext{"No API key provided."}
		}
	}

	if !CompareBcrypt(ctx.Hash, providedKey) {
		return false, apiKeyAccessContext{"The provided API is invalid."}
	}

	return true, nil
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
