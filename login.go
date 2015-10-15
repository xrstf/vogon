package main

import (
	"net/http"
	"strings"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
)

type loginData struct {
	LoginName string
}

func loginFormAction() response {
	return renderTemplate(200, "login", loginData{""})
}

func loginAction(m *SessionMiddleware, req *http.Request, res http.ResponseWriter, db *sqlx.Tx) response {
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

	if !CompareBcrypt(*user.Password, password) {
		return renderTemplate(403, "login", loginData{validated})
	}

	s, err := m.StartSession(user, res)
	if err != nil {
		return renderTemplate(500, "login", loginData{validated})
	}

	NewAuditLog(db, req).LogLogin(user.Id)

	// mark the current session as logged in
	s.User = user.Id

	err = user.TouchOnLogin()
	if err != nil {
		panic(err)
	}

	return redirect(302, "/")
}

func logoutAction(session *Session, m *SessionMiddleware, res http.ResponseWriter) response {
	m.EndSession(session, res)

	return redirect(302, "/")
}

func setupLoginCtrl(app *martini.ClassicMartini) {
	app.Get("/login", loginFormAction)
	app.Post("/login", loginAction)
	app.Post("/logout", sessions.RequireLogin, sessions.RequireCsrfToken, logoutAction)
}
