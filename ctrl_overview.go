package main

import "github.com/go-martini/martini"
import "github.com/martini-contrib/csrf"
import "github.com/martini-contrib/sessionauth"
import "github.com/martini-contrib/sessions"
import "github.com/jmoiron/sqlx"
import "net/http"
import "strings"

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

type loginData struct {
	LoginName string
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

func loginFormAction() response {
	return renderTemplate(200, "login", loginData{""})
}

func loginAction(params martini.Params, session sessions.Session, req *http.Request, db *sqlx.Tx) response {
	login := strings.TrimSpace(req.FormValue("login"))
	password := strings.TrimSpace(req.FormValue("password"))

	validated, err := validateSafeString(login, "login")
	if err != nil {
		return renderTemplate(403, "login", loginData{""})
	}

	user := findUserByLogin(login, true, db)
	if user == nil || user.Deleted != nil {
		return renderTemplate(403, "login", loginData{validated})
	}

	if *user.Password != password {
		return renderTemplate(403, "login", loginData{validated})
	}

	NewAuditLog(db, req).LogLogin(user.Id)

	err = sessionauth.UpdateUser(session, user)
	if err != nil {
		panic(err)
	}

	err = user.TouchOnLogin()
	if err != nil {
		panic(err)
	}

	target := req.URL.Query().Get(sessionauth.RedirectParam)

	if len(target) == 0 {
		target = "/"
	}

	return redirect(302, target)
}

func setupOverviewCtrl(app *martini.ClassicMartini) {
	app.Get("/", sessionauth.LoginRequired, overviewIndexAction)
	app.Get("/login", loginFormAction)
	app.Post("/login", loginAction)
}
