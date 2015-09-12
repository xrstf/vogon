package main

import (
	"net/http"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/sessionauth"
)

type accessLogEntry struct {
	Date   string
	Origin string
}

type overviewData struct {
	layoutData

	Secrets    int
	Consumers  int
	Users      int
	RecentHits int
	AuditLog   []AuditLogEntry
	AccessLog  []accessLogEntry
}

func overviewIndexAction(user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	secrets := countResultSet{}
	db.Get(&secrets, "SELECT COUNT(*) AS `num` FROM `secret`")

	users := countResultSet{}
	db.Get(&users, "SELECT COUNT(*) AS `num` FROM `user` WHERE `deleted` IS NULL")

	consumers := countResultSet{}
	db.Get(&consumers, "SELECT COUNT(*) AS `num` FROM `consumer` WHERE `deleted` = 0")

	recentHits := countResultSet{}
	db.Get(&recentHits, "SELECT COUNT(*) AS `num` FROM `access_log`")

	auditLog := NewAuditLog(db, req)

	data := &overviewData{
		layoutData: NewLayoutData("Dashboard", "dashboard", user, x.GetToken()),
		Secrets:    secrets.Count,
		Consumers:  consumers.Count,
		Users:      users.Count,
		RecentHits: recentHits.Count,
		AuditLog:   auditLog.FindAll(10, 0),
		AccessLog:  make([]accessLogEntry, 0),
	}

	return renderTemplate(200, "overview/index", data)
}

func setupOverviewCtrl(app *martini.ClassicMartini) {
	app.Get("/", sessionauth.LoginRequired, overviewIndexAction)
}
