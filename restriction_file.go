package main

import (
	"errors"
	"net/http"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
// restriction handler

type FileRestriction struct{}

func (FileRestriction) GetIdentifier() string {
	return "file"
}

func (FileRestriction) GetNullContext() interface{} {
	return newFileContext("")
}

func (FileRestriction) IsNullContext(ctx interface{}) bool {
	asserted, ok := ctx.(*fileContext)
	return ok && asserted.Filename == ""
}

func (FileRestriction) SerializeForm(req *http.Request, enabled bool, oldCtx interface{}) (interface{}, error) {
	filename := strings.TrimSpace(req.FormValue("restriction_file_filename"))

	if enabled && len(filename) == 0 {
		return nil, errors.New("No filename given.")
	}

	return newFileContext(filename), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type fileContext struct {
	Filename string `json:"filename"`
}

func newFileContext(filename string) *fileContext {
	return &fileContext{filename}
}
