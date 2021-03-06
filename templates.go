package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/oxtoacart/bpool"
)

type TemplateManager struct {
	rootDir   string
	bufpool   *bpool.BufferPool
	templates map[string]*template.Template
	functions template.FuncMap
}

type layoutData struct {
	PageTitle      string
	ActiveMenuItem string
	CurrentUser    *User
	CsrfToken      string
	BaseUrl        string
}

func NewLayoutData(title string, active string, user *User, csrfToken string) layoutData {
	return layoutData{title, active, user, csrfToken, config.Server.BaseUrl}
}

func NewTemplateManager(rootDir string) *TemplateManager {
	tm := &TemplateManager{}

	tm.bufpool = bpool.NewBufferPool(64)
	tm.rootDir = rootDir
	tm.functions = template.FuncMap{
		"time": func(value string) template.HTML {
			t, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.Local)
			if err != nil {
				return template.HTML("(invalid date given)")
			}

			// get timezone information
			iso := t.Format("2006-01-02T15:04:05-0700")
			pretty := t.Format("Mon, Jan 2 2006 15:04")

			return template.HTML("<time class=\"rel\" datetime=\"" + iso + "\">" + pretty + "</time>")
		},

		"shorten": func(value string, maxlen int) string {
			length := len(value)

			if length <= maxlen {
				return value
			}

			halfs := maxlen / 2
			runes := []rune(value)

			return fmt.Sprintf("%s…%s", string(runes[:halfs]), string(runes[(length-halfs):]))
		},
	}

	tm.Init()

	return tm
}

func (tm *TemplateManager) Init() {
	tm.templates = make(map[string]*template.Template)

	// load auxiliary templates
	includes, err := filepath.Glob(tm.rootDir + "/includes/*.html")
	if err != nil {
		log.Fatal(err)
	}

	templates, err := filepath.Glob(tm.rootDir + "/*/*.html")
	if err != nil {
		log.Fatal(err)
	}

	// Generate our templates map from our layouts/ and includes/ directories
	for _, tpl := range templates {
		directory := filepath.Base(filepath.Dir(tpl))

		if directory == "includes" {
			continue
		}

		identifier := directory + "/" + strings.TrimSuffix(filepath.Base(tpl), ".html")
		files := append(includes, tpl)

		tm.Add(identifier, files)
	}

	// load un-namespaces files (do not inherit the includes)
	raws, err := filepath.Glob(tm.rootDir + "/*.html")
	if err != nil {
		log.Fatal(err)
	}

	// Generate our templates map from our layouts/ and includes/ directories
	for _, tpl := range raws {
		identifier := strings.TrimSuffix(filepath.Base(tpl), ".html")

		tm.Add(identifier, []string{tpl})
	}
}

func (tm *TemplateManager) Add(identifier string, templates []string) {
	tpl := template.New(identifier)

	tm.templates[identifier] = template.Must(tpl.Funcs(tm.functions).ParseFiles(templates...))
}

func (tm *TemplateManager) Has(templateName string) bool {
	_, ok := tm.templates[templateName]
	return ok
}

func (tm *TemplateManager) Render(templateName string, data interface{}) (string, error) {
	template, ok := tm.templates[templateName]
	if !ok {
		return "", errors.New("Template '" + templateName + "' does not exist.")
	}

	buf := tm.bufpool.Get()
	defer tm.bufpool.Put(buf)

	err := template.ExecuteTemplate(buf, "root", data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
