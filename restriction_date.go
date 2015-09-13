package main

import (
	"fmt"
	"time"

	// "log"
	"net/http"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type DateRestriction struct{}

func (DateRestriction) GetIdentifier() string {
	return "date"
}

func (DateRestriction) GetNullContext() interface{} {
	return newDateContext(false, false, false, false, false, false, false)
}

func (DateRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*dateContext)
	if !ok {
		return false
	}

	for _, d := range asserted.Week() {
		if d.Enabled {
			return false
		}
	}

	return true
}

func (r DateRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	ctx := r.GetNullContext().(*dateContext)

	for _, day := range ctx.Week() {
		num := day.Num
		value := req.FormValue(fmt.Sprintf("restriction_date_%d", num))

		ctx.EnabledDays[num] = value == "1"
	}

	return ctx, nil
}

func (DateRestriction) CheckAccess(request *http.Request, context interface{}) (bool, interface{}) {
	// ctx, err := context.(*tlsCertContext)
	// if err {
	// 	return false, apiKeyAccessContext{"Invalid context given. This should never happen."}
	// }

	return false, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type dateContext struct {
	EnabledDays []bool `json:"enabled"`
}

// a single day of the week, num is 0-6 (Sun-Mon)
type dateDay struct {
	Num     int
	Name    string
	Enabled bool
}

func newDateContext(mon bool, tue bool, wed bool, thu bool, fri bool, sat bool, sun bool) *dateContext {
	return &dateContext{[]bool{sun, mon, tue, wed, thu, fri, sat}}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// utilities

func (c *dateContext) Monday() bool {
	return c.EnabledDays[time.Monday]
}

func (c *dateContext) Tuesday() bool {
	return c.EnabledDays[time.Tuesday]
}

func (c *dateContext) Wednesday() bool {
	return c.EnabledDays[time.Wednesday]
}

func (c *dateContext) Thursday() bool {
	return c.EnabledDays[time.Thursday]
}

func (c *dateContext) Friday() bool {
	return c.EnabledDays[time.Friday]
}

func (c *dateContext) Saturday() bool {
	return c.EnabledDays[time.Saturday]
}

func (c *dateContext) Sunday() bool {
	return c.EnabledDays[time.Sunday]
}

func (c *dateContext) Week() []dateDay {
	return []dateDay{
		{int(time.Monday), "Monday", c.Monday()},
		{int(time.Tuesday), "Tuesday", c.Tuesday()},
		{int(time.Wednesday), "Wednesday", c.Wednesday()},
		{int(time.Thursday), "Thursday", c.Thursday()},
		{int(time.Friday), "Friday", c.Friday()},
		{int(time.Saturday), "Saturday", c.Saturday()},
		{int(time.Sunday), "Sunday", c.Sunday()},
	}
}
