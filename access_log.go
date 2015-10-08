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
	Id          int     `db:"id"`
	Secret      *int    `db:"secret_id"`
	Consumer    *int    `db:"consumer_id"`
	RequestedAt string  `db:"requested_at"`
	OriginIp    string  `db:"origin_ip"`
	Status      int     `db:"status"`
	Context     *string `db:"context"`
	RequestBody *string `db:"request_body"`
	_db         *sqlx.Tx
}

func (a *AccessLogEntry) Save() error {
	if a.Id > 0 {
		return errors.New("Existing access log entries cannot be updated.")
	}

	result, err := a._db.Exec(
		"INSERT INTO `access_log` (`secret_id`, `consumer_id`, `requested_at`, `origin_ip`, `status`, `context`, `request_body`) VALUES (?,?,NOW(),?,?,?,?)",
		a.Secret, a.Consumer, a.OriginIp, a.Status, a.Context, a.RequestBody,
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
	FindAll(int, int) []AccessLogEntry
	Find([]int, []int, []int, int, int) []AccessLogEntry
	Count([]int, []int, []int) int

	LogNotFound(*Consumer, *Secret, *http.Request)
	LogAccess(*Consumer, *Secret, *http.Request, int, interface{})
}

type accessLogStruct struct {
	db *sqlx.Tx
}

func NewAccessLog(db *sqlx.Tx) AccessLog {
	return &accessLogStruct{db}
}

func (a *accessLogStruct) FindAll(limit int, offset int) []AccessLogEntry {
	empty := make([]int, 0)

	return a.Find(empty, empty, empty, limit, offset)
}

func (a *accessLogStruct) Find(secretIds []int, consumerIds []int, states []int, limit int, offset int) []AccessLogEntry {
	list := make([]AccessLogEntry, 0)
	where := a.buildWhereStatement(secretIds, consumerIds, states)
	limitStmt := a.buildLimitStatement(limit, offset)

	a.db.Select(&list, "SELECT `id`, `secret_id`, `consumer_id`, `requested_at`, `origin_ip`, `status`, `context`, `request_body` FROM `access_log` WHERE "+where+" ORDER BY id DESC "+limitStmt)

	for i := range list {
		list[i]._db = a.db
	}

	return list
}

func (a *accessLogStruct) Count(secretIds []int, consumerIds []int, states []int) int {
	count := 0
	where := a.buildWhereStatement(secretIds, consumerIds, states)

	a.db.Get(&count, "SELECT COUNT(*) AS `c` FROM `access_log` WHERE "+where)

	return count
}

func (a *accessLogStruct) LogNotFound(consumer *Consumer, secret *Secret, req *http.Request) {
	a.LogAccess(consumer, secret, req, 404, nil)
}

func (a *accessLogStruct) LogAccess(consumer *Consumer, secret *Secret, req *http.Request, status int, ctx interface{}) {
	entry := AccessLogEntry{}
	entry.OriginIp = getIP(req)
	entry.Status = status
	entry._db = a.db

	if consumer != nil {
		entry.Consumer = &consumer.Id
	}

	if secret != nil {
		entry.Secret = &secret.Id
	}

	if ctx != nil {
		asserted, ok := ctx.(map[string]interface{})

		if !ok || len(asserted) > 0 {
			json, err := json.Marshal(ctx)
			if err != nil {
				panic(err)
			}

			str := string(json)
			entry.Context = &str
		}
	}

	err := entry.Save()
	if err != nil {
		panic(err)
	}
}

func (a *accessLogStruct) buildWhereStatement(secretIds []int, consumerIds []int, states []int) string {
	where := "1"

	if len(secretIds) > 0 {
		where += fmt.Sprintf(" AND `secret_id` IN (%s)", concatIntList(secretIds))
	}

	if len(consumerIds) > 0 {
		where += fmt.Sprintf(" AND `consumer_id` IN (%s)", concatIntList(consumerIds))
	}

	if len(states) > 0 {
		where += fmt.Sprintf(" AND `status` IN (%s)", concatIntList(states))
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

	Entries   []AccessLogEntry
	Secrets   []accessSecret
	Consumers []accessConsumer
	States    map[int]bool
	Query     template.URL
	Pager     pager.Pager
}

func (a *accessLogListData) HasStatus(status int) bool {
	_, ok := a.States[status]
	return ok
}

func accessLogIndexAction(user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	selectedSecrets := getIntList(req, "secrets[]")
	selectedConsumers := getIntList(req, "consumers[]")
	selectedStates := getIntList(req, "status[]")

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
	entries := accessLog.Find(selectedSecrets, selectedConsumers, selectedStates, limit, offset)
	total := accessLog.Count(selectedSecrets, selectedConsumers, selectedStates)

	pgr := pager.NewBasicPager(page, total, limit)
	data := &accessLogListData{layoutData: NewLayoutData("Access Log", "accesslog", user, x.GetToken())}

	data.Entries = entries
	data.Pager = pgr
	data.Secrets = []accessSecret{}
	data.Consumers = []accessConsumer{}
	data.States = make(map[int]bool)

	for _, secret := range findAllSecrets(false, db) {
		selected := isInIntList(secret.Id, selectedSecrets)
		data.Secrets = append(data.Secrets, accessSecret{secret.Id, secret.Name, selected})
	}

	for _, consumer := range findAllConsumers(db) {
		selected := isInIntList(consumer.Id, selectedConsumers)
		data.Consumers = append(data.Consumers, accessConsumer{consumer.Id, consumer.Name, selected})
	}

	for _, status := range selectedStates {
		data.States[status] = true
	}

	// re-create the query string
	url := url.Values{}
	addIntsToUrl(&url, "secrets[]", selectedSecrets)
	addIntsToUrl(&url, "consumers[]", selectedConsumers)
	addIntsToUrl(&url, "status[]", selectedStates)

	data.Query = template.URL(url.Encode())

	return renderTemplate(200, "access_log/index", data)
}

func setupAccessLogCtrl(app *martini.ClassicMartini) {
	app.Group("/accesslog", func(r martini.Router) {
		app.Get("", accessLogIndexAction)
	}, sessionauth.LoginRequired)
}
