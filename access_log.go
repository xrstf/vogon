package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/sessionauth"
	"github.com/xrstf/pager"
)

type AccessLogEntry struct {
	Id                    int     `db:"id"`
	Secret                *int    `db:"secret_id"`
	Consumer              *int    `db:"consumer_id"`
	RequestedAt           string  `db:"requested_at"`
	OriginIp              string  `db:"origin_ip"`
	AuthenticationSuccess bool    `db:"authentication_success"`
	RestrictionSuccess    bool    `db:"restriction_success"`
	AuthenticationContext *string `db:"authentication_context"`
	RestrictionContext    *string `db:"restriction_context"`
	RequestBody           *string `db:"request_body"`
	_db                   *sqlx.Tx
}

func (a *AccessLogEntry) Save() error {
	if a.Id > 0 {
		return errors.New("Existing access log entries cannot be updated.")
	}

	result, err := a._db.Exec(
		"INSERT INTO `access_log` (`secret_id`, `consumer_id`, `requested_at`, `origin_ip`, `authentication_success`, `restriction_success`, `authentication_context`, `restriction_context`, `request_body`) VALUES (?,?,NOW(),?,?,?,?,?,?)",
		a.Secret, a.Consumer, a.OriginIp, a.AuthenticationSuccess, a.RestrictionSuccess, a.AuthenticationContext, a.RestrictionContext, a.RequestBody,
	)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	a.Id = int(id)

	return nil
}

func (e *AccessLogEntry) GetSecret() *Secret {
	if e.Secret == nil {
		return nil
	}

	return findSecret(*e.Secret, false, e._db)
}

func (e *AccessLogEntry) GetConsumer() *Consumer {
	if e.Consumer == nil {
		return nil
	}

	return findConsumer(*e.Consumer, e._db)
}

type AccessLog interface {
	Find([]int, []int, *bool, *bool, int, int) []AccessLogEntry
	Count([]int, []int, *bool, *bool) int

	LogNotFound(*Consumer, *Secret, *http.Request)
	LogAccess(*Consumer, *Secret, *http.Request, bool, interface{}, bool, interface{})
}

type accessLogStruct struct {
	db *sqlx.Tx
}

func NewAccessLog(db *sqlx.Tx) AccessLog {
	return &accessLogStruct{db}
}

func (a *accessLogStruct) Find(secretIds []int, consumerIds []int, authSuccess *bool, restrictionSuccess *bool, limit int, offset int) []AccessLogEntry {
	list := make([]AccessLogEntry, 0)
	where := a.buildWhereStatement(secretIds, consumerIds, authSuccess, restrictionSuccess)
	limitStmt := a.buildLimitStatement(limit, offset)

	a.db.Select(&list, "SELECT `id`, `secret_id`, `consumer_id`, `requested_at`, `origin_ip`, `authentication_success`, `restriction_success`, `authentication_context`, `restriction_context`, `request_body` FROM `access_log` WHERE "+where+" ORDER BY id DESC "+limitStmt)

	for i := range list {
		list[i]._db = a.db
	}

	return list
}

func (a *accessLogStruct) Count(secretIds []int, consumerIds []int, authSuccess *bool, restrictionSuccess *bool) int {
	count := 0
	where := a.buildWhereStatement(secretIds, consumerIds, authSuccess, restrictionSuccess)

	a.db.Get(&count, "SELECT COUNT(*) AS `c` FROM `access_log` WHERE "+where)

	return count
}

func (a *accessLogStruct) LogNotFound(consumer *Consumer, secret *Secret, req *http.Request) {
	a.LogAccess(consumer, secret, req, false, nil, false, nil)
}

func (a *accessLogStruct) LogAccess(consumer *Consumer, secret *Secret, req *http.Request, authSuccess bool, authCtx interface{}, restrictionSuccess bool, restrictionCtx interface{}) {
	entry := AccessLogEntry{}
	entry.OriginIp = getIP(req)
	entry.AuthenticationSuccess = authSuccess
	entry.RestrictionSuccess = restrictionSuccess
	entry._db = a.db

	if consumer != nil {
		entry.Consumer = &consumer.Id
	}

	if secret != nil {
		entry.Secret = &secret.Id
	}

	if authCtx != nil {
		json, err := json.Marshal(authCtx)
		if err != nil {
			panic(err)
		}

		str := string(json)
		entry.AuthenticationContext = &str
	}

	if restrictionCtx != nil {
		json, err := json.Marshal(restrictionCtx)
		if err != nil {
			panic(err)
		}

		str := string(json)
		entry.RestrictionContext = &str
	}

	err := entry.Save()
	if err != nil {
		panic(err)
	}
}

func (a *accessLogStruct) buildWhereStatement(secretIds []int, consumerIds []int, authSuccess *bool, restrictionSuccess *bool) string {
	where := "1"

	if len(secretIds) > 0 {
		where += fmt.Sprintf(" AND `secret_id` IN (%s)", concatIntList(secretIds))
	}

	if len(consumerIds) > 0 {
		where += fmt.Sprintf(" AND `consumer_id` IN (%s)", concatIntList(consumerIds))
	}

	if authSuccess != nil {
		where += fmt.Sprintf(" AND `authentication_success` = %t", *authSuccess)
	}

	if restrictionSuccess != nil {
		where += fmt.Sprintf(" AND `restriction_success` = %t", *restrictionSuccess)
	}

	return where
}

func (a *accessLogStruct) buildLimitStatement(limit int, offset int) string {
	// return a sane fallback
	if limit <= 0 {
		return "LIMIT 10"
	}

	if offset > 0 {
		return fmt.Sprintf("LIMIT %d,%d", offset, limit)
	}

	return fmt.Sprintf("LIMIT %d", limit)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Access Log controllers
////////////////////////////////////////////////////////////////////////////////////////////////////

type accessSecret struct {
	Id       int
	Name     string
	Selected bool
}

type accessConsumer struct {
	Id       int
	Name     string
	Selected bool
}

type accessLogListData struct {
	layoutData

	Entries               []AccessLogEntry
	Secrets               []accessSecret
	Consumers             []accessConsumer
	AuthenticationSuccess string
	RestrictionSuccess    string
	Query                 template.URL
	Pager                 pager.Pager
}

func accessLogIndexAction(user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	var authSuccess *bool = nil
	var restrSuccess *bool = nil

	selectedSecrets := getIntList(req, "secrets[]")
	selectedConsumers := getIntList(req, "consumers[]")
	selectedAuth := req.FormValue("authentication")
	selectedRestriction := req.FormValue("restriction")

	if len(selectedAuth) > 0 && selectedAuth != "all" {
		selected := selectedAuth == "success"
		authSuccess = &selected
	}

	if len(selectedRestriction) > 0 && selectedRestriction != "all" {
		selected := selectedRestriction == "success"
		restrSuccess = &selected
	}

	// get current page
	page, err := strconv.Atoi(req.FormValue("page"))
	if err != nil {
		page = 0
	}

	if page < 0 {
		page = 0
	}

	limit := 25
	offset := page * limit

	accessLog := NewAccessLog(db)
	entries := accessLog.Find(selectedSecrets, selectedConsumers, authSuccess, restrSuccess, limit, offset)
	total := accessLog.Count(selectedSecrets, selectedConsumers, authSuccess, restrSuccess)

	pgr := pager.NewBasicPager(page, total, limit)
	data := &accessLogListData{layoutData: NewLayoutData("Access Log", "accesslog", user, x.GetToken())}

	data.Entries = entries
	data.Pager = pgr
	data.Secrets = []accessSecret{}
	data.Consumers = []accessConsumer{}
	data.AuthenticationSuccess = "all"
	data.RestrictionSuccess = "all"

	if authSuccess != nil {
		if *authSuccess == true {
			data.AuthenticationSuccess = "success"
		} else {
			data.AuthenticationSuccess = "failure"
		}
	}

	if restrSuccess != nil {
		if *restrSuccess == true {
			data.RestrictionSuccess = "success"
		} else {
			data.RestrictionSuccess = "failure"
		}
	}

	for _, secret := range findAllSecrets(false, db) {
		selected := isInIntList(secret.Id, selectedSecrets)
		data.Secrets = append(data.Secrets, accessSecret{secret.Id, secret.Name, selected})
	}

	for _, consumer := range findAllConsumers(db) {
		selected := isInIntList(consumer.Id, selectedConsumers)
		data.Consumers = append(data.Consumers, accessConsumer{consumer.Id, consumer.Name, selected})
	}

	// re-create the query string
	url := url.Values{}
	addIntsToUrl(&url, "secrets[]", selectedSecrets)
	addIntsToUrl(&url, "consumers[]", selectedConsumers)

	if authSuccess != nil {
		url.Set("authentication", fmt.Sprintf("%t", authSuccess))
	}

	if restrSuccess != nil {
		url.Set("restriction", fmt.Sprintf("%t", restrSuccess))
	}

	data.Query = template.URL(url.Encode())

	return renderTemplate(200, "access_log/index", data)
}

func setupAccessLogCtrl(app *martini.ClassicMartini) {
	app.Group("/accesslog", func(r martini.Router) {
		app.Get("", accessLogIndexAction)
	}, sessionauth.LoginRequired)
}
