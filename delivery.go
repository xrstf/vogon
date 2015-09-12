package main

import (
	"net/http"
	"strings"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessions"
)

func deliverSecretAction(params martini.Params, session sessions.Session, req *http.Request, db *sqlx.Tx) response {
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

func setupDeliveryCtrl(app *martini.ClassicMartini) {
	app.Get("/get/:consumer/:secret", deliverSecretAction)
	app.Post("/get/:consumer/:secret", deliverSecretAction)
}
