package main

import (
	"net/http"
	"reflect"

	"github.com/codegangsta/inject"
	"github.com/go-martini/martini"
)

func newReturnHandler() martini.ReturnHandler {
	return func(ctx martini.Context, vals []reflect.Value) {
		rv := ctx.Get(inject.InterfaceOf((*http.ResponseWriter)(nil)))
		res := rv.Interface().(http.ResponseWriter)
		resp := vals[0]

		if canDeref(resp) {
			resp = resp.Elem()
		}

		asserted, ok := resp.Interface().(response)
		if !ok {
			panic("Controller must return a response.")
		}

		// write the headers type BEFORE writing anything else, or else the gzip
		// middleware would set an autodetected header, which would be "app/x-gzipped".
		contentType := "text/html"
		content := asserted.Content

		if asserted.Status == 302 {
			res.Header().Set("Location", asserted.Content)

			content = "You are being redirected to " + asserted.Content
			contentType = "text/plain"
		}

		res.Header().Set("Content-Type", contentType+"; charset=utf-8")
		res.WriteHeader(asserted.Status)
		res.Write([]byte(content))
	}
}

func canDeref(val reflect.Value) bool {
	return val.Kind() == reflect.Interface || val.Kind() == reflect.Ptr
}
