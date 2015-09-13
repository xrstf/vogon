package main

import (
	"errors"
	"io/ioutil"
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

type fileRestrictionAccessContext struct {
	Error string `json:"error"`
}

func (FileRestriction) CheckAccess(request *http.Request, context interface{}) (bool, interface{}) {
	ctx, okay := context.(*fileContext)
	if !okay {
		return false, fileRestrictionAccessContext{"Invalid context given. This should never happen."}
	}

	fn := ctx.Filename
	if len(fn) == 0 {
		return false, fileRestrictionAccessContext{"No filename configured."}
	}

	// TODO: only read one byte, we don't need more
	content, err := ioutil.ReadFile(fn)

	if err != nil {
		return false, fileRestrictionAccessContext{"Could not read from file '" + fn + "': " + err.Error()}
	}

	if len(content) == 0 {
		return false, fileRestrictionAccessContext{"File '" + fn + "' is empty."}
	}

	return true, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// context representation

type fileContext struct {
	Filename string `json:"filename"`
}

func newFileContext(filename string) *fileContext {
	return &fileContext{filename}
}
