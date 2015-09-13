package main

import (
	"errors"
	"net/http"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type OriginIpRestriction struct{}

func (OriginIpRestriction) GetIdentifier() string {
	return "origin_ip"
}

func (OriginIpRestriction) GetNullContext() interface{} {
	return newOriginIpContext("")
}

func (OriginIpRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*originIpContext)
	return ok && asserted.Ruleset == ""
}

func (OriginIpRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	ruleset := strings.TrimSpace(req.FormValue("restriction_origin_ip_ruleset"))

	if enabled && len(ruleset) == 0 {
		return nil, errors.New("No rules given.")
	}

	return newOriginIpContext(ruleset), nil
}

func (OriginIpRestriction) CheckAccess(request *http.Request, context interface{}) (bool, interface{}) {
	// ctx, err := context.(*tlsCertContext)
	// if err {
	// 	return false, apiKeyAccessContext{"Invalid context given. This should never happen."}
	// }

	return false, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type originIpContext struct {
	Ruleset string `json:"ruleset"`
}

func newOriginIpContext(ruleset string) *originIpContext {
	return &originIpContext{ruleset}
}
