package main

import (
	"net/http"
	"time"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
)

type dashboardData struct {
	layoutData

	Secrets    int
	Consumers  int
	Users      int
	RecentHits int
	AuditLog   []AuditLogEntry
	AccessLog  []AccessLogEntry
}

func dashboardAction(user *User, req *http.Request, session *Session, db *sqlx.Tx) response {
	secrets := countResultSet{}
	db.Get(&secrets, "SELECT COUNT(*) AS `num` FROM `secret`")

	users := countResultSet{}
	db.Get(&users, "SELECT COUNT(*) AS `num` FROM `user` WHERE `deleted` IS NULL")

	consumers := countResultSet{}
	db.Get(&consumers, "SELECT COUNT(*) AS `num` FROM `consumer` WHERE `deleted` = 0")

	now := time.Now()
	limit := now.AddDate(0, 0, -7).Format("2006-01-02")

	recentHits := countResultSet{}
	db.Get(&recentHits, "SELECT COUNT(*) AS `num` FROM `access_log` WHERE requested_at >= '"+limit+"'")

	auditLog := NewAuditLog(db, req)
	accessLog := NewAccessLog(db)

	data := &dashboardData{
		layoutData: NewLayoutData("Dashboard", "dashboard", user, session.CsrfToken),
		Secrets:    secrets.Count,
		Consumers:  consumers.Count,
		Users:      users.Count,
		RecentHits: recentHits.Count,
		AuditLog:   auditLog.FindAll(10, 0),
		AccessLog:  accessLog.FindAll(10, 0),
	}

	return renderTemplate(200, "dashboard/index", data)
}

func setupDashboardCtrl(app *martini.ClassicMartini) {
	app.Get("/", sessions.RequireLogin, dashboardAction)
}
