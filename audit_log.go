package main

import "fmt"
import "strings"
import "regexp"
import "net/http"
import "net/url"
import "strconv"
import "html/template"
import "github.com/go-martini/martini"
import "github.com/martini-contrib/csrf"
import "github.com/martini-contrib/sessionauth"
import "github.com/jmoiron/sqlx"
import "github.com/xrstf/pager"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Audit Log model
////////////////////////////////////////////////////////////////////////////////////////////////////

type AuditLogEntry struct {
	Id        int      `db:"id"`
	Secret    *int     `db:"secret_id"`
	Consumer  *int     `db:"consumer_id"`
	User      *int     `db:"user_id"`
	Action    string   `db:"action"`
	CreatedAt string   `db:"created_at"`
	CreatedBy int      `db:"created_by"`
	OriginIp  string   `db:"origin_ip"`
	UserAgent *string  `db:"user_agent"`
	Context   *Context `db:"context"`
	_db       *sqlx.Tx
}

func (e *AuditLogEntry) GetSecret() *Secret {
	if e.Secret == nil {
		return nil
	}

	return findSecret(*e.Secret, false, e._db)
}

func (e *AuditLogEntry) GetConsumer() *Consumer {
	if e.Consumer == nil {
		return nil
	}

	return findConsumer(*e.Consumer, e._db)
}

func (e *AuditLogEntry) GetUser() *User {
	if e.User == nil {
		return nil
	}

	return findUser(*e.User, false, e._db)
}

func (e *AuditLogEntry) GetCreator() *User {
	return findUser(e.CreatedBy, false, e._db)
}

type AuditLog interface {
	FindAll(int, int) []AuditLogEntry
	FindBySecrets([]int, int, int) []AuditLogEntry
	FindByConsumers([]int, int, int) []AuditLogEntry
	FindByUsers([]int, int, int) []AuditLogEntry
	FindByCreators([]int, int, int) []AuditLogEntry
	FindByActions([]string, int, int) []AuditLogEntry

	CountAll() int
	CountBySecrets([]int) int
	CountByConsumers([]int) int
	CountByUsers([]int) int
	CountByCreators([]int) int
	CountByActions([]string) int

	Find([]int, []int, []int, []int, []string, int, int) []AuditLogEntry
	Count([]int, []int, []int, []int, []string) int

	LogLogin(int)
	LogUserCreated(int, int)
	LogUserUpdated(int, int)
	LogUserDeleted(int, int)
	LogSecretCreated(int, int)
	LogSecretUpdated(int, int)
	LogSecretDeleted(int, int)
	LogConsumerCreated(int, int)
	LogConsumerUpdated(int, int)
	LogConsumerDeleted(int, int)
}

type auditLogStruct struct {
	db  *sqlx.Tx
	req *http.Request
}

func NewAuditLog(db *sqlx.Tx, req *http.Request) AuditLog {
	return &auditLogStruct{db, req}
}

func (a *auditLogStruct) FindAll(limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(e, e, e, e, []string{}, limit, offset)
}

func (a *auditLogStruct) FindBySecrets(secretIds []int, limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(secretIds, e, e, e, []string{}, limit, offset)
}

func (a *auditLogStruct) FindByConsumers(consumerIds []int, limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(e, consumerIds, e, e, []string{}, limit, offset)
}

func (a *auditLogStruct) FindByUsers(userIds []int, limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(e, e, userIds, e, []string{}, limit, offset)
}

func (a *auditLogStruct) FindByCreators(creatorIds []int, limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(e, e, e, creatorIds, []string{}, limit, offset)
}

func (a *auditLogStruct) FindByActions(actions []string, limit int, offset int) []AuditLogEntry {
	e := []int{}
	return a.Find(e, e, e, e, actions, limit, offset)
}

func (a *auditLogStruct) Find(secretIds []int, consumerIds []int, userIds []int, creatorIds []int, actions []string, limit int, offset int) []AuditLogEntry {
	list := make([]AuditLogEntry, 0)
	where := a.buildWhereStatement(secretIds, consumerIds, userIds, creatorIds, actions)
	limitStmt := a.buildLimitStatement(limit, offset)

	a.db.Select(&list, "SELECT `id`, `secret_id`, `consumer_id`, `user_id`, `action`, `created_by`, `created_at`, `origin_ip`, `user_agent`, `context` FROM `audit_log` WHERE "+where+" ORDER BY id DESC "+limitStmt)

	for i := range list {
		list[i]._db = a.db
	}

	return list
}

func (a *auditLogStruct) CountAll() int {
	e := []int{}
	return a.Count(e, e, e, e, []string{})
}

func (a *auditLogStruct) CountBySecrets(secretIds []int) int {
	e := []int{}
	return a.Count(secretIds, e, e, e, []string{})
}

func (a *auditLogStruct) CountByConsumers(consumerIds []int) int {
	e := []int{}
	return a.Count(e, consumerIds, e, e, []string{})
}

func (a *auditLogStruct) CountByUsers(userIds []int) int {
	e := []int{}
	return a.Count(e, e, userIds, e, []string{})
}

func (a *auditLogStruct) CountByCreators(creatorIds []int) int {
	e := []int{}
	return a.Count(e, e, e, creatorIds, []string{})
}

func (a *auditLogStruct) CountByActions(actions []string) int {
	e := []int{}
	return a.Count(e, e, e, e, actions)
}

func (a *auditLogStruct) Count(secretIds []int, consumerIds []int, userIds []int, creatorIds []int, actions []string) int {
	count := 0
	where := a.buildWhereStatement(secretIds, consumerIds, userIds, creatorIds, actions)

	a.db.Get(&count, "SELECT COUNT(*) AS `c` FROM `audit_log` WHERE "+where)

	return count
}

func (a *auditLogStruct) LogLogin(userId int) {
	a.logAction(-1, -1, userId, userId, "user-login", nil)
}

func (a *auditLogStruct) LogUserCreated(creatorId int, createdUserId int) {
	a.logAction(-1, -1, createdUserId, creatorId, "user-created", nil)
}

func (a *auditLogStruct) LogUserUpdated(editorId int, editedUserId int) {
	a.logAction(-1, -1, editedUserId, editorId, "user-updated", nil)
}

func (a *auditLogStruct) LogUserDeleted(editorId int, deletedUserId int) {
	a.logAction(-1, -1, deletedUserId, editorId, "user-deleted", nil)
}

func (a *auditLogStruct) LogSecretCreated(secretId int, userId int) {
	a.logAction(secretId, -1, -1, userId, "secret-created", nil)
}

func (a *auditLogStruct) LogSecretUpdated(secretId int, userId int) {
	a.logAction(secretId, -1, -1, userId, "secret-updated", nil)
}

func (a *auditLogStruct) LogSecretDeleted(secretId int, userId int) {
	a.logAction(secretId, -1, -1, userId, "secret-deleted", nil)
}

func (a *auditLogStruct) LogConsumerCreated(consumerId int, userId int) {
	a.logAction(-1, consumerId, -1, userId, "consumer-created", nil)
}

func (a *auditLogStruct) LogConsumerUpdated(consumerId int, userId int) {
	a.logAction(-1, consumerId, -1, userId, "consumer-updated", nil)
}

func (a *auditLogStruct) LogConsumerDeleted(consumerId int, userId int) {
	a.logAction(-1, consumerId, -1, userId, "consumer-deleted", nil)
}

func (a *auditLogStruct) logAction(secretId int, consumerId int, userId, creatorId int, action string, context interface{}) {
	var secret *int = nil
	var consumer *int = nil
	var user *int = nil
	var ctx []byte = nil

	if secretId > 0 {
		secret = &secretId
	}

	if consumerId > 0 {
		consumer = &consumerId
	}

	if userId > 0 {
		user = &userId
	}

	if context != nil {
		tmp := PackContext(context)
		ctx = []byte(*tmp)
	}

	var userAgent *string = nil

	if ua := a.req.UserAgent(); len(ua) > 0 {
		userAgent = &ua
	}

	_, err := a.db.Exec(
		"INSERT INTO `audit_log` (`secret_id`, `consumer_id`, `user_id`, `action`, `created_at`, `created_by`, `origin_ip`, `user_agent`, `context`) VALUES (?,?,?,?,NOW(),?,?,?,?)",
		secret, consumer, user, action, creatorId, getIP(a.req), userAgent, ctx,
	)

	if err != nil {
		panic(err)
	}
}

func (a *auditLogStruct) buildWhereStatement(secretIds []int, consumerIds []int, userIds []int, creatorIds []int, actions []string) string {
	where := "1"

	if len(secretIds) > 0 {
		where += fmt.Sprintf(" AND `secret_id` IN (%s)", concatIntList(secretIds))
	}

	if len(consumerIds) > 0 {
		where += fmt.Sprintf(" AND `consumer_id` IN (%s)", concatIntList(consumerIds))
	}

	if len(userIds) > 0 {
		where += fmt.Sprintf(" AND `user_id` IN (%s)", concatIntList(userIds))
	}

	if len(creatorIds) > 0 {
		where += fmt.Sprintf(" AND `created_by` IN (%s)", concatIntList(creatorIds))
	}

	if len(actions) > 0 {
		valid := make([]string, 0)
		checker := regexp.MustCompile(`^[a-z0-9_-]+$`)

		for _, action := range actions {
			if checker.MatchString(action) {
				valid = append(valid, action)
			}
		}

		if len(valid) > 0 {
			where += fmt.Sprintf(" AND `action` IN (%s)", concatStringList(valid))
		}
	}

	return where
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

func (a *auditLogStruct) buildLimitStatement(limit int, offset int) string {
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
// Audit Log controllers
////////////////////////////////////////////////////////////////////////////////////////////////////

type auditSecret struct {
	Id       int
	Name     string
	Selected bool
}

type auditConsumer struct {
	Id       int
	Name     string
	Selected bool
}

type auditUser struct {
	Id       int
	Name     string
	Selected bool
}

type auditLogListData struct {
	layoutData

	Entries   []AuditLogEntry
	Secrets   []auditSecret
	Consumers []auditConsumer
	Users     []auditUser
	Creators  []auditUser
	Actions   map[string]bool
	Query     template.URL
	Pager     pager.Pager
}

func (a *auditLogListData) HasAction(action string) bool {
	_, ok := a.Actions[action]
	return ok
}

func auditLogIndexAction(user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	selectedSecrets := getIntList(req, "secrets[]")
	selectedConsumers := getIntList(req, "consumers[]")
	selectedUsers := getIntList(req, "users[]")
	selectedCreators := getIntList(req, "creators[]")
	selectedActions := getStringList(req, "actions[]")

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

	auditLog := NewAuditLog(db, req)
	entries := auditLog.Find(selectedSecrets, selectedConsumers, selectedUsers, selectedCreators, selectedActions, limit, offset)
	total := auditLog.Count(selectedSecrets, selectedConsumers, selectedUsers, selectedCreators, selectedActions)

	pgr := pager.NewBasicPager(page, total, limit)
	data := &auditLogListData{layoutData: NewLayoutData("Audit Log", "auditlog", user, x.GetToken())}

	data.Entries = entries
	data.Pager = pgr
	data.Secrets = []auditSecret{}
	data.Consumers = []auditConsumer{}
	data.Users = []auditUser{}
	data.Creators = []auditUser{}
	data.Actions = make(map[string]bool)

	for _, secret := range findAllSecrets(false, db) {
		selected := isInIntList(secret.Id, selectedSecrets)
		data.Secrets = append(data.Secrets, auditSecret{secret.Id, secret.Name, selected})
	}

	for _, consumer := range findAllConsumers(db) {
		selected := isInIntList(consumer.Id, selectedConsumers)
		data.Consumers = append(data.Consumers, auditConsumer{consumer.Id, consumer.Name, selected})
	}

	for _, user := range findAllUsers(false, db) {
		selected := isInIntList(user.Id, selectedUsers)
		data.Users = append(data.Users, auditUser{user.Id, user.Name, selected})

		selected = isInIntList(user.Id, selectedCreators)
		data.Creators = append(data.Creators, auditUser{user.Id, user.Name, selected})
	}

	for _, action := range selectedActions {
		data.Actions[action] = true
	}

	// re-create the query string
	url := url.Values{}
	addIntsToUrl(&url, "secrets[]", selectedSecrets)
	addIntsToUrl(&url, "consumers[]", selectedConsumers)
	addIntsToUrl(&url, "users[]", selectedUsers)
	addIntsToUrl(&url, "creators[]", selectedCreators)

	if len(selectedActions) > 0 {
		for i, value := range selectedActions {
			if i == 0 {
				url.Set("actions[]", value)
			} else {
				url.Add("actions[]", value)
			}
		}
	}

	data.Query = template.URL(url.Encode())

	return renderTemplate(200, "audit_log/index", data)
}

func setupAuditLogCtrl(app *martini.ClassicMartini) {
	app.Group("/auditlog", func(r martini.Router) {
		app.Get("", auditLogIndexAction)
	}, sessionauth.LoginRequired)
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
