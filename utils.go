package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func matches(regex string, target string) bool {
	matched, err := regexp.MatchString(regex, target)
	return matched && err == nil
}

type response struct {
	Status  int
	Content string
}

type countResultSet struct {
	Count int `db:"num"`
}

func newResponse(status int, content string) response {
	return response{status, content}
}

func renderTemplate(status int, tpl string, data interface{}) response {
	page, err := templateManager.Render(tpl, data)
	if err != nil {
		panic(err)
	}

	return newResponse(status, page)
}

func renderError(status int, message string) response {
	data := make(map[string]string)
	data["Error"] = message
	data["PageTitle"] = "Aw snap!"
	data["ActiveMenuItem"] = ""

	return renderTemplate(status, "error", data)
}

func redirect(status int, target string) response {
	return newResponse(status, target)
}

func validateSafeString(tainted string, name string) (string, error) {
	tainted = strings.ToLower(tainted)

	if len(tainted) == 0 {
		return "", errors.New("The " + name + " cannot be empty.")
	}

	if !matches("^[a-z0-9_-]+$", tainted) {
		return "", errors.New("The " + name + " may only contain a-z, 0-9, - (dash) and _ (underscore).")
	}

	if !matches("^[a-z]", tainted) || !matches("[a-z0-9]$", tainted) {
		return "", errors.New("The " + name + " must start with a letter and end with either a letter or a number.")
	}

	return tainted, nil
}

type Context []byte

func PackContext(ctx interface{}) *Context {
	json, err := json.Marshal(ctx)
	if err != nil {
		log.Panicln(err)
	}

	result := Context(json)
	return &result
}

func (c *Context) Unpack(target interface{}) {
	err := json.Unmarshal(*c, target)
	if err != nil {
		log.Panicln(err)
	}
}

func getIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		panic(err)
	}

	return ip
}

func isInIntList(needle int, haystack []int) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}

	return false
}

func isInStringList(needle string, haystack []string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}

	return false
}

func getStringList(req *http.Request, name string) []string {
	list, okay := req.URL.Query()[name]
	if okay {
		return list
	}

	return []string{}
}

func getIntList(req *http.Request, name string) []int {
	list := getStringList(req, name)
	result := []int{}

	for _, identifier := range list {
		id, err := strconv.Atoi(identifier)
		if err == nil {
			result = append(result, id)
		}
	}

	return result
}

func addIntsToUrl(url *url.Values, name string, values []int) {
	for i, value := range values {
		if i == 0 {
			url.Set(name, strconv.Itoa(value))
		} else {
			url.Add(name, strconv.Itoa(value))
		}
	}
}

func concatIntList(values []int) string {
	list := make([]string, 0, len(values))

	for _, value := range values {
		list = append(list, strconv.Itoa(value))
	}

	return strings.Join(list, ", ")
}

func concatStringList(values []string) string {
	list := make([]string, 0, len(values))

	for _, value := range values {
		list = append(list, "'"+value+"'") // we assume that value is a clean string with no fancy crap
	}

	return strings.Join(list, ", ")
}
