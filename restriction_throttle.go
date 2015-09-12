package main

import "net/http"
import "strings"
import "strconv"
import "errors"

type ThrottleUnit int

const (
	ThrottleSecond ThrottleUnit = iota
	ThrottleMinute
	ThrottleHour
	ThrottleDay
)

type unit struct {
	Num      ThrottleUnit
	Name     string
	Selected bool
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type ThrottleRestriction struct{}

func (ThrottleRestriction) GetIdentifier() string {
	return "throttle"
}

func (ThrottleRestriction) GetNullContext() interface{} {
	return newThrottleContext(0, ThrottleHour)
}

func (ThrottleRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*throttleContext)
	return ok && asserted.MaxHits <= 0 && asserted.Unit == ThrottleHour
}

func (ThrottleRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	max, err := strconv.Atoi(strings.TrimSpace(req.FormValue("restriction_throttle_max")))
	if err != nil || max < 0 {
		return nil, errors.New("Malformed number given for the request limit.")
	}

	unit, err := strconv.Atoi(strings.TrimSpace(req.FormValue("restriction_throttle_unit")))
	if err != nil {
		return nil, errors.New("Malformed throttle unit given.")
	}

	tunit := ThrottleUnit(unit)
	if tunit < ThrottleSecond || tunit > ThrottleDay {
		return nil, errors.New("Invalid throttle unit given.")
	}

	return newThrottleContext(max, tunit), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type throttleContext struct {
	MaxHits int          `json:"max-hits"`
	Unit    ThrottleUnit `json:"unit"`
}

func newThrottleContext(max int, unit ThrottleUnit) *throttleContext {
	return &throttleContext{max, unit}
}

func (c *throttleContext) Units() []unit {
	return []unit{
		{ThrottleSecond, "Second", c.Unit == ThrottleSecond},
		{ThrottleMinute, "Minute", c.Unit == ThrottleMinute},
		{ThrottleHour, "Hour", c.Unit == ThrottleHour},
		{ThrottleDay, "Day", c.Unit == ThrottleDay},
	}
}
