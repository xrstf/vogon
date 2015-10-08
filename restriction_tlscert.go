package main

import (
	"errors"
	"net/http"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type TlsCertRestriction struct{}

func (TlsCertRestriction) GetIdentifier() string {
	return "tls_cert"
}

func (TlsCertRestriction) GetNullContext() interface{} {
	return newTlsCertContext("", 0)
}

func (TlsCertRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*tlsCertContext)
	if !ok {
		return false
	}

	return asserted.Issuer == "" && asserted.Serial == 0
}

func (TlsCertRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	value := strings.TrimSpace(req.FormValue("auth_api_key_key"))

	if len(value) == 0 {
		if oldCtx == nil {
			return nil, errors.New("No API key given.")
		}

		return oldCtx, nil
	}

	return newTlsCertContext("", 42), nil
}

type tlsCertAccessContext struct {
	Error string `json:"error"`
}

func (TlsCertRestriction) CheckAccess(request *http.Request, context interface{}) (bool, interface{}) {
	// ctx, okay := context.(*tlsCertContext)
	// if !okay {
	// 	return false, apiKeyAccessContext{"Invalid context given. This should never happen."}
	// }

	return false, nil
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
