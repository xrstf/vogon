package main

import (
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
	AuthenticationStatus  int     `db:"authentication_status"`
	RestrictionStatus     int     `db:"restriction_status"`
	AuthenticationContext *string `db:"authentication_context"`
	RestrictionContext    *string `db:"restriction_context"`
	RequestBody           *string `db:"request_body"`
	_db                   *sqlx.Tx
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
	Find([]int, []int, []int, []int, int, int) []AccessLogEntry
	Count([]int, []int, []int, []int) int
}

type accessLogStruct struct {
	db *sqlx.Tx
}

func NewAccessLog(db *sqlx.Tx) AccessLog {
	return &accessLogStruct{db}
}

func (a *accessLogStruct) Find(secretIds []int, consumerIds []int, authStati []int, restrictionStati []int, limit int, offset int) []AccessLogEntry {
	list := make([]AccessLogEntry, 0)
	where := a.buildWhereStatement(secretIds, consumerIds, authStati, restrictionStati)
	limitStmt := a.buildLimitStatement(limit, offset)

	a.db.Select(&list, "SELECT `id`, `secret_id`, `consumer_id`, `requested_at`, `origin_ip`, `authentication_status`, `restriction_status`, `authentication_context`, `restriction_context`, `request_body` FROM `access_log` WHERE "+where+" ORDER BY id DESC "+limitStmt)

	for i := range list {
		list[i]._db = a.db
	}

	return list
}

func (a *accessLogStruct) Count(secretIds []int, consumerIds []int, authStati []int, restrictionStati []int) int {
	count := 0
	where := a.buildWhereStatement(secretIds, consumerIds, authStati, restrictionStati)

	a.db.Get(&count, "SELECT COUNT(*) AS `c` FROM `access_log` WHERE "+where)

	return count
}

func (a *accessLogStruct) Log(userId int) {
	// a.logAction(-1, -1, userId, userId, "user-login", nil)
}

func (a *accessLogStruct) buildWhereStatement(secretIds []int, consumerIds []int, authStati []int, restrictionStati []int) string {
	where := "1"

	if len(secretIds) > 0 {
		where += fmt.Sprintf(" AND `secret_id` IN (%s)", concatIntList(secretIds))
	}

	if len(consumerIds) > 0 {
		where += fmt.Sprintf(" AND `consumer_id` IN (%s)", concatIntList(consumerIds))
	}

	if len(authStati) > 0 {
		where += fmt.Sprintf(" AND `authentication_status` IN (%s)", concatIntList(authStati))
	}

	if len(restrictionStati) > 0 {
		where += fmt.Sprintf(" AND `restriction_status` IN (%s)", concatIntList(restrictionStati))
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

	Entries             []AccessLogEntry
	Secrets             []accessSecret
	Consumers           []accessConsumer
	AuthenticationStati map[int]bool
	RestrictionStati    map[int]bool
	Query               template.URL
	Pager               pager.Pager
}

func (a *accessLogListData) HasAuthenticationStatus(status int) bool {
	_, ok := a.AuthenticationStati[status]
	return ok
}

func (a *accessLogListData) HasRestrictionStatus(status int) bool {
	_, ok := a.RestrictionStati[status]
	return ok
}

func accessLogIndexAction(user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	selectedSecrets := getIntList(req, "secrets[]")
	selectedConsumers := getIntList(req, "consumers[]")
	selectedAuthStati := getIntList(req, "auth[]")
	selectedRestrictionStati := getIntList(req, "restr[]")

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
	entries := accessLog.Find(selectedSecrets, selectedConsumers, selectedAuthStati, selectedRestrictionStati, limit, offset)
	total := accessLog.Count(selectedSecrets, selectedConsumers, selectedAuthStati, selectedRestrictionStati)

	pgr := pager.NewBasicPager(page, total, limit)
	data := &accessLogListData{layoutData: NewLayoutData("Access Log", "accesslog", user, x.GetToken())}

	data.Entries = entries
	data.Pager = pgr
	data.Secrets = []accessSecret{}
	data.Consumers = []accessConsumer{}
	data.AuthenticationStati = make(map[int]bool)
	data.RestrictionStati = make(map[int]bool)

	for _, secret := range findAllSecrets(false, db) {
		selected := isInIntList(secret.Id, selectedSecrets)
		data.Secrets = append(data.Secrets, accessSecret{secret.Id, secret.Name, selected})
	}

	for _, consumer := range findAllConsumers(db) {
		selected := isInIntList(consumer.Id, selectedConsumers)
		data.Consumers = append(data.Consumers, accessConsumer{consumer.Id, consumer.Name, selected})
	}

	for _, status := range selectedAuthStati {
		data.AuthenticationStati[status] = true
	}

	for _, status := range selectedRestrictionStati {
		data.RestrictionStati[status] = true
	}

	// re-create the query string
	url := url.Values{}
	addIntsToUrl(&url, "secrets[]", selectedSecrets)
	addIntsToUrl(&url, "consumers[]", selectedConsumers)
	addIntsToUrl(&url, "auth[]", selectedAuthStati)
	addIntsToUrl(&url, "restr[]", selectedRestrictionStati)

	data.Query = template.URL(url.Encode())

	return renderTemplate(200, "access_log/index", data)
}

func setupAccessLogCtrl(app *martini.ClassicMartini) {
	app.Group("/accesslog", func(r martini.Router) {
		app.Get("", accessLogIndexAction)
	}, sessionauth.LoginRequired)
}
