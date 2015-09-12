package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type HitLimitRestriction struct{}

func (HitLimitRestriction) GetIdentifier() string {
	return "hit_limit"
}

func (HitLimitRestriction) GetNullContext() interface{} {
	return newHitLimitContext(0, 0)
}

func (HitLimitRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*hitLimitContext)
	return ok && asserted.Limit <= 0
}

func (r HitLimitRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	limit, err := strconv.Atoi(strings.TrimSpace(req.FormValue("restriction_hit_limit_limit")))
	if err != nil {
		return nil, err
	}

	// TODO: Handle form values more cleverly. Calculate the diff and adjust the remaining value accordingly.
	//       Forbid illegal moves (i.e. don't allow to reduce to remaining < 0).

	if enabled && limit <= 0 {
		return nil, errors.New("The request limit must be greater than zero.")
	}

	remaining := limit
	if oldCtx != nil {
		asserted, ok := oldCtx.(*hitLimitContext)
		if ok && !r.IsNullContext(asserted) {
			remaining = asserted.Remaining
		}
	}

	return newHitLimitContext(limit, remaining), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type hitLimitContext struct {
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
}

func newHitLimitContext(limit int, remaining int) *hitLimitContext {
	return &hitLimitContext{limit, remaining}
}
