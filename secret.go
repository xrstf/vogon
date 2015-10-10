package main

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/sessionauth"
)

type Secret struct {
	Id        int     `db:"id"`
	Name      string  `db:"name"`
	Slug      string  `db:"slug"`
	Secret    []byte  `db:"secret"`
	CreatedAt string  `db:"created_at"`
	UpdatedAt *string `db:"updated_at"`
	CreatedBy int     `db:"created_by"`
	UpdatedBy *int    `db:"updated_by"`

	_db *sqlx.Tx
}

func findAllSecrets(loadSecrets bool, db *sqlx.Tx) []Secret {
	list := make([]Secret, 0)
	secretCol := ""

	if loadSecrets {
		secretCol = ", `secret`"
	}

	db.Select(&list, "SELECT `id`, `slug`, `name`, `created_at`, `created_by`, `updated_at`, `updated_by`"+secretCol+" FROM `secret` WHERE 1 ORDER BY name")

	for i := range list {
		list[i]._db = db
	}

	return list
}

func findSecret(id int, loadSecret bool, db *sqlx.Tx) *Secret {
	secret := &Secret{}
	secret._db = db

	secretCol := ""

	if loadSecret {
		secretCol = ", `secret`"
	}

	db.Get(secret, "SELECT `id`, `slug`, `name`, `created_at`, `created_by`, `updated_at`, `updated_by`"+secretCol+" FROM `secret` WHERE `id` = ?", id)
	if secret.Id == 0 {
		return nil
	}

	return secret
}

func findSecretBySlug(slug string, loadSecret bool, db *sqlx.Tx) *Secret {
	secret := &Secret{}
	secret._db = db

	secretCol := ""

	validated, err := validateSafeString(slug, "slug")
	if err != nil {
		return nil
	}

	if loadSecret {
		secretCol = ", `secret`"
	}

	db.Get(secret, "SELECT `id`, `slug`, `name`, `created_at`, `created_by`, `updated_at`, `updated_by`"+secretCol+" FROM `secret` WHERE `slug` = ?", validated)
	if secret.Id == 0 {
		return nil
	}

	return secret
}

func (s *Secret) Save() error {
	if s.Id <= 0 {
		result, err := s._db.Exec(
			"INSERT INTO `secret` (`name`, `slug`, `secret`, `created_at`, `updated_at`, `created_by`, `updated_by`) VALUES (?,?,?,NOW(),NULL,?,NULL)",
			s.Name, s.Slug, s.Secret, s.CreatedBy,
		)

		if err != nil {
			return err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return err
		}

		s.Id = int(id)
	} else {
		var err error

		// if the secret wasn't fetched, don't attempt to update it
		if s.Secret == nil {
			_, err = s._db.Exec(
				"UPDATE `secret` SET `name` = ?, `slug` = ?, `updated_at` = NOW(), `updated_by` = ? WHERE `id` = ?",
				s.Name, s.Slug, s.UpdatedBy, s.Id,
			)
		} else {
			_, err = s._db.Exec(
				"UPDATE `secret` SET `name` = ?, `slug` = ?, `secret` = ?, `updated_at` = NOW(), `updated_by` = ? WHERE `id` = ?",
				s.Name, s.Slug, s.Secret, s.UpdatedBy, s.Id,
			)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Secret) Delete() error {
	_, err := s._db.Exec("DELETE FROM `secret` WHERE `id` = ?", s.Id)
	if err != nil {
		return err
	}

	return nil
}

func (s *Secret) GetCreator() *User {
	return findUser(s.CreatedBy, false, s._db)
}

func (s *Secret) GetUpdater() *User {
	if s.UpdatedBy == nil {
		return nil
	}

	return findUser(*s.UpdatedBy, false, s._db)
}

type secretListData struct {
	layoutData

	Secrets []Secret
}

type secretFormData struct {
	layoutData

	Secret     int
	Name       string
	NameError  string
	Slug       string
	SlugError  string
	BodyError  string
	OtherError string
}

func (data *secretFormData) fromSecret(s *Secret) {
	data.Secret = s.Id
	data.Name = s.Name
	data.Slug = s.Slug
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP Handlers
////////////////////////////////////////////////////////////////////////////////////////////////////

func secretsIndexAction(user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := &secretListData{NewLayoutData("Secrets", "secrets", user, x.GetToken()), findAllSecrets(false, db)}

	return renderTemplate(200, "secrets/index", data)
}

func secretsAddAction(user *User, x csrf.CSRF) response {
	data := &secretFormData{layoutData: NewLayoutData("Add Secret", "secrets", user, x.GetToken())}

	return renderTemplate(200, "secrets/form", data)
}

func secretsCreateAction(req *http.Request, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := &secretFormData{layoutData: NewLayoutData("Add Secret", "secrets", user, x.GetToken())}
	name := strings.TrimSpace(req.FormValue("name"))
	slug := strings.TrimSpace(req.FormValue("slug"))
	body := strings.TrimSpace(req.FormValue("body"))

	data.Name = name
	data.Slug = slug

	if len(name) == 0 {
		data.NameError = "The name cannot be empty."
		return renderTemplate(400, "secrets/form", data)
	}

	validated, err := validateSafeString(slug, "slug")
	if err != nil {
		data.SlugError = err.Error()
		return renderTemplate(400, "secrets/form", data)
	}

	existing := findSecretBySlug(validated, false, db)
	if existing != nil {
		data.SlugError = "This slug is already in use."
		return renderTemplate(400, "secrets/form", data)
	}

	if len(body) == 0 {
		data.BodyError = "The body cannot be empty."
		return renderTemplate(400, "secrets/form", data)
	}

	encrypted, err := Encrypt([]byte(body))
	if err != nil {
		data.OtherError = "Could not encrypt secret: " + err.Error()
		return renderTemplate(500, "secrets/form", data)
	}

	secret := &Secret{
		Id:        -1,
		Name:      name,
		Slug:      validated,
		Secret:    encrypted,
		CreatedBy: user.Id,
		_db:       db,
	}

	err = secret.Save()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogSecretCreated(secret.Id, user.Id)

	return redirect(302, "/secrets")
}

func secretsEditAction(params martini.Params, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	secret := findSecret(id, false, db)
	if secret == nil {
		return renderError(404, "Secret could not be found.")
	}

	data := &secretFormData{layoutData: NewLayoutData("Edit Secret", "secrets", user, x.GetToken())}
	data.fromSecret(secret)

	return renderTemplate(200, "secrets/form", data)
}

func secretsUpdateAction(params martini.Params, req *http.Request, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	secret := findSecret(id, false, db)
	if secret == nil {
		return renderError(404, "Secret could not be found.")
	}

	data := &secretFormData{layoutData: NewLayoutData("Edit Secret", "secrets", user, x.GetToken())}
	name := strings.TrimSpace(req.FormValue("name"))
	slug := strings.TrimSpace(req.FormValue("slug"))
	body := strings.TrimSpace(req.FormValue("body"))

	data.Secret = secret.Id
	data.Name = name
	data.Slug = slug

	if len(name) == 0 {
		data.NameError = "The name cannot be empty."
		return renderTemplate(400, "secrets/form", data)
	}

	validated, err := validateSafeString(slug, "slug")
	if err != nil {
		data.SlugError = err.Error()
		return renderTemplate(400, "secrets/form", data)
	}

	s := findSecretBySlug(validated, false, db)
	if s != nil && s.Id != secret.Id {
		data.SlugError = "This slug is already in use."
		return renderTemplate(400, "secrets/form", data)
	}

	secret.Name = name
	secret.Slug = validated
	secret.UpdatedBy = &user.Id

	if len(body) > 0 {
		encrypted, err := Encrypt([]byte(body))
		if err != nil {
			data.OtherError = "Could not encrypt secret: " + err.Error()
			return renderTemplate(500, "secrets/form", data)
		}

		secret.Secret = encrypted
	}

	err = secret.Save()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogSecretUpdated(secret.Id, user.Id)

	return redirect(302, "/secrets")
}

func secretsDeleteConfirmAction(params martini.Params, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	secret := findSecret(id, false, db)
	if secret == nil {
		return renderError(404, "Secret could not be found.")
	}

	data := &secretFormData{layoutData: NewLayoutData("Delete Secret", "secrets", user, x.GetToken())}
	data.fromSecret(secret)

	return renderTemplate(200, "secrets/confirmation", data)
}

func secretsDeleteAction(params martini.Params, user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	secret := findSecret(id, false, db)
	if secret == nil {
		return renderError(404, "Secret could not be found.")
	}

	data := &secretFormData{layoutData: NewLayoutData("Delete Secret", "secrets", user, x.GetToken())}
	data.fromSecret(secret)

	err = secret.Delete()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogSecretDeleted(secret.Id, user.Id)

	return redirect(302, "/secrets")
}

func setupSecretsCtrl(app *martini.ClassicMartini) {
	app.Group("/secrets", func(r martini.Router) {
		app.Get("", secretsIndexAction)
		app.Get("/add", secretsAddAction)
		app.Post("", csrf.Validate, secretsCreateAction)
		app.Get("/:id", secretsEditAction)
		app.Put("/:id", csrf.Validate, secretsUpdateAction)
		app.Delete("/:id", csrf.Validate, secretsDeleteAction)
		app.Get("/:id/delete", secretsDeleteConfirmAction)
	}, sessionauth.LoginRequired)
}
