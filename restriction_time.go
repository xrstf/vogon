package main

import "net/http"
import "strings"
import "errors"

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type TimeRestriction struct{}

func (TimeRestriction) GetIdentifier() string {
	return "time"
}

func (TimeRestriction) GetNullContext() interface{} {
	return newTimeContext("")
}

func (TimeRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*timeContext)
	return ok && asserted.Ruleset == ""
}

func (TimeRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	ruleset := strings.TrimSpace(req.FormValue("restriction_time_ruleset"))

	if enabled && len(ruleset) == 0 {
		return nil, errors.New("No rules given.")
	}

	return newTimeContext(ruleset), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type timeContext struct {
	Ruleset string `json:"ruleset"`
}

func newTimeContext(ruleset string) *timeContext {
	return &timeContext{ruleset}
}
