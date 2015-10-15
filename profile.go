package main

import (
	"net/http"
	"strings"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
)

type profileData struct {
	layoutData

	Name          string
	NameError     string
	LoginName     string
	LoginError    string
	PasswordError string
	OtherError    string
}

func profileAction(user *User, session *Session) response {
	data := &profileData{
		layoutData: NewLayoutData("Profile", "profile", user, session.CsrfToken),
		Name:       user.Name,
		LoginName:  user.LoginName,
	}

	return renderTemplate(200, "profile/form", data)
}

func updateProfileAction(user *User, req *http.Request, session *Session, db *sqlx.Tx) response {
	data := &profileData{
		layoutData: NewLayoutData("Profile", "profile", user, session.CsrfToken),
		Name:       user.Name,
		LoginName:  user.LoginName,
	}

	name := strings.TrimSpace(req.FormValue("name"))
	login := strings.TrimSpace(req.FormValue("login"))

	data.Name = name
	data.LoginName = login

	if len(name) == 0 {
		data.NameError = "Your name cannot be empty."
		return renderTemplate(400, "profile/form", data)
	}

	validated, err := validateSafeString(login, "login")
	if err != nil {
		data.LoginError = err.Error()
		return renderTemplate(400, "profile/form", data)
	}

	existing := findUserByLogin(validated, false, db)
	if existing != nil && existing.Id != user.Id {
		data.LoginError = "This login is already in use."
		return renderTemplate(400, "profile/form", data)
	}

	user.Name = name
	user.LoginName = validated

	err = user.Save()
	if err != nil {
		data.OtherError = err.Error()
		return renderTemplate(500, "profile/form", data)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogUserUpdated(user.Id, user.Id)

	return redirect(302, "/profile")
}

func changePasswordAction(user *User, req *http.Request, session *Session, db *sqlx.Tx) response {
	data := &profileData{
		layoutData: NewLayoutData("Profile", "profile", user, session.CsrfToken),
		Name:       user.Name,
		LoginName:  user.LoginName,
	}

	password := strings.TrimSpace(req.FormValue("password"))

	if len(password) == 0 {
		data.PasswordError = "Your password cannot be empty."
		return renderTemplate(400, "profile/form", data)
	}

	if !CompareBcrypt(*user.Password, password) {
		data.PasswordError = "This was not your current password."
		return renderTemplate(400, "profile/form", data)
	}

	hashed := string(HashBcrypt(password))
	user.Password = &hashed

	err := user.Save()
	if err != nil {
		data.OtherError = err.Error()
		return renderTemplate(500, "profile/form", data)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogUserUpdated(user.Id, user.Id)

	return redirect(302, "/profile")
}

func setupProfileCtrl(app *martini.ClassicMartini) {
	app.Get("/profile", sessions.RequireLogin, profileAction)
	app.Put("/profile", sessions.RequireLogin, sessions.RequireCsrfToken, updateProfileAction)
	app.Put("/profile/password", sessions.RequireLogin, sessions.RequireCsrfToken, changePasswordAction)
}
