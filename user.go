package main

import "github.com/go-martini/martini"
import "github.com/martini-contrib/csrf"
import "github.com/martini-contrib/sessionauth"
import "github.com/jmoiron/sqlx"
import "net/http"
import "strings"
import "strconv"

type User struct {
	Id          int     `db:"id"`
	LoginName   string  `db:"login"`
	Password    *string `db:"password"`
	Name        string  `db:"name"`
	LastLoginAt *string `db:"last_login_at"`
	Deleted     *string `db:"deleted"`

	_db *sqlx.Tx
}

func findAllUsers(loadPasswords bool, db *sqlx.Tx) []User {
	list := make([]User, 0)
	passwordCol := ""

	if loadPasswords {
		passwordCol = ", `password`"
	}

	db.Select(&list, "SELECT `id`, `login`, `name`, `last_login_at`, `deleted`"+passwordCol+" FROM `user` WHERE `deleted` IS NULL ORDER BY `name`, `login`")

	for i := range list {
		list[i]._db = db
	}

	return list
}

func findUser(id int, loadPassword bool, db *sqlx.Tx) *User {
	user := &User{}
	user._db = db

	passwordCol := ""

	if loadPassword {
		passwordCol = ", `password`"
	}

	db.Get(user, "SELECT `id`, `login`, `name`, `last_login_at`, `deleted`"+passwordCol+" FROM `user` WHERE `id` = ?", id)
	if user.Id == 0 {
		return nil
	}

	return user
}

func findUserByLogin(login string, loadPassword bool, db *sqlx.Tx) *User {
	user := &User{}
	user._db = db

	passwordCol := ""

	validated, err := validateSafeString(login, "login")
	if err != nil {
		return nil
	}

	if loadPassword {
		passwordCol = ", `password`"
	}

	db.Get(user, "SELECT `id`, `login`, `name`, `last_login_at`, `deleted`"+passwordCol+" FROM `user` WHERE `login` = ? AND `deleted` IS NULL", validated)
	if user.Id == 0 {
		return nil
	}

	return user
}

func (u *User) Save() error {
	if u.Id <= 0 {
		result, err := u._db.Exec(
			"INSERT INTO `user` (`name`, `login`, `password`, `last_login_at`, `deleted`) VALUES (?,?,?,NULL,?)",
			u.Name, u.LoginName, u.Password, u.Deleted,
		)

		if err != nil {
			return err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return err
		}

		u.Id = int(id)
	} else {
		var err error

		// if the password wasn't fetched, don't attempt to update it
		// deleted=0 is to guarantee that we do not modify deleted users
		if u.Password == nil {
			_, err = u._db.Exec(
				"UPDATE `user` SET `name` = ?, `login` = ?, `last_login_at` = ?, `deleted` = ? WHERE `id` = ? AND `deleted` IS NULL",
				u.Name, u.LoginName, u.LastLoginAt, u.Deleted, u.Id,
			)
		} else {
			_, err = u._db.Exec(
				"UPDATE `user` SET `name` = ?, `login` = ?, `last_login_at` = ?, `password` = ?, `deleted` = ? WHERE `id` = ? AND `deleted` IS NULL",
				u.Name, u.LoginName, u.LastLoginAt, u.Password, u.Deleted, u.Id,
			)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (u *User) Delete() error {
	_, err := u._db.Exec("UPDATE `user` SET `deleted` = NOW() WHERE `id` = ?", u.Id)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) TouchOnLogin() error {
	_, err := u._db.Exec("UPDATE `user` SET `last_login_at` = NOW() WHERE `id` = ?", u.Id)
	return err
}

// interface for sessionauth.User

// Return whether this user is logged in or not
func (u *User) IsAuthenticated() bool {
	return u.Id > 0
}

// Return the unique identifier of this user object
// Return this as a string so that the CSRF middleware can properly detect and use it (it requires
// either strings or int64s).
func (u *User) UniqueId() interface{} {
	return strconv.Itoa(u.Id)
}

// Set any flags or extra data that should be available
// @unused
func (u *User) Login() {
	// nop
}

// Clear any sensitive data out of the user
// @unused
func (u *User) Logout() {
	// nop
}

// Populate this user object with values
// @unused
func (u *User) GetById(id interface{}) error {
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP Handlers
////////////////////////////////////////////////////////////////////////////////////////////////////

type userListData struct {
	layoutData

	Users []User
}

type userFormData struct {
	layoutData

	User          int
	Name          string
	NameError     string
	LoginName     string
	LoginError    string
	PasswordError string
	LastLoginAt   string
	Deleted       string
	OtherError    string
}

func (data *userFormData) fromUser(u *User) {
	data.User = u.Id
	data.Name = u.Name
	data.LoginName = u.LoginName
	data.LastLoginAt = ""
	data.Deleted = ""

	if u.LastLoginAt != nil {
		data.LastLoginAt = *u.LastLoginAt
	}

	if u.Deleted != nil {
		data.Deleted = *u.Deleted
	}
}

func usersIndexAction(user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := &userListData{NewLayoutData("Users", "users", user, x.GetToken()), make([]User, 0)}

	// find users (do not even select the user itself, we don't need it)
	db.Select(&data.Users, "SELECT `id`, `login`, `name`, `last_login_at`, `deleted` FROM `user` WHERE `deleted` IS NULL ORDER BY `name`")

	for i := range data.Users {
		data.Users[i]._db = db
	}

	return renderTemplate(200, "users/index", data)
}

func usersAddAction(user *User, x csrf.CSRF) response {
	data := &userFormData{layoutData: NewLayoutData("Add User", "users", user, x.GetToken())}

	return renderTemplate(200, "users/form", data)
}

func usersCreateAction(req *http.Request, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := &userFormData{layoutData: NewLayoutData("Add User", "users", user, x.GetToken())}
	name := strings.TrimSpace(req.FormValue("name"))
	login := strings.TrimSpace(req.FormValue("login"))
	password := strings.TrimSpace(req.FormValue("password"))

	data.Name = name
	data.LoginName = login

	if len(name) == 0 {
		data.NameError = "The name cannot be empty."
		return renderTemplate(400, "users/form", data)
	}

	validated, err := validateSafeString(login, "login")
	if err != nil {
		data.LoginError = err.Error()
		return renderTemplate(400, "users/form", data)
	}

	s := findUserByLogin(validated, false, db)
	if s != nil {
		data.LoginError = "This login is already in use."
		return renderTemplate(400, "users/form", data)
	}

	if len(password) < 4 {
		data.PasswordError = "The passphrase must be at least 4 characters long."
		return renderTemplate(400, "users/form", data)
	}

	newUser := &User{
		Id:        -1,
		Name:      name,
		LoginName: validated,
		Password:  &password,
		_db:       db,
	}

	err = newUser.Save()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogUserCreated(user.Id, newUser.Id)

	return redirect(302, "/users")
}

func usersEditAction(params martini.Params, currentUser *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	user := findUser(id, false, db)
	if user == nil {
		return renderError(404, "User could not be found.")
	}

	data := &userFormData{layoutData: NewLayoutData("Edit User", "users", currentUser, x.GetToken())}
	data.fromUser(user)

	return renderTemplate(200, "users/form", data)
}

func usersUpdateAction(params martini.Params, req *http.Request, currentUser *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	subject := findUser(id, false, db)
	if subject == nil {
		return renderError(404, "User could not be found.")
	}

	if subject.Id == currentUser.Id {
		return renderError(403, "You cannot edit yourself.")
	}

	data := &userFormData{layoutData: NewLayoutData("Edit User", "users", currentUser, x.GetToken())}
	name := strings.TrimSpace(req.FormValue("name"))
	login := strings.TrimSpace(req.FormValue("login"))
	password := strings.TrimSpace(req.FormValue("password"))

	data.User = subject.Id
	data.Name = name
	data.LoginName = login

	if subject.Deleted != nil {
		data.OtherError = "This user has been deleted and cannot be edited anymore."
		return renderTemplate(409, "users/form", data)
	}

	if len(name) == 0 {
		data.NameError = "The name cannot be empty."
		return renderTemplate(400, "users/form", data)
	}

	validated, err := validateSafeString(login, "login")
	if err != nil {
		data.LoginError = err.Error()
		return renderTemplate(400, "users/form", data)
	}

	existing := findUserByLogin(validated, false, db)
	if existing != nil && existing.Id != subject.Id {
		data.LoginError = "This login is already in use."
		return renderTemplate(400, "users/form", data)
	}

	subject.Name = name
	subject.LoginName = validated

	if len(password) > 0 {
		subject.Password = &password
	}

	err = subject.Save()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogUserUpdated(currentUser.Id, subject.Id)

	return redirect(302, "/users")
}

func usersDeleteConfirmAction(params martini.Params, current *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	subject := findUser(id, false, db)
	if subject == nil {
		return renderError(404, "User could not be found.")
	}

	if subject.Id == current.Id {
		return renderError(403, "You cannot delete yourself.")
	}

	if subject.Deleted != nil {
		return renderError(409, "This user has already been deleted. Show some mercy.")
	}

	data := &userFormData{layoutData: NewLayoutData("Delete User", "users", current, x.GetToken())}
	data.fromUser(subject)

	return renderTemplate(200, "users/confirmation", data)
}

func usersDeleteAction(params martini.Params, current *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	subject := findUser(id, false, db)
	if subject == nil {
		return renderError(404, "User could not be found.")
	}

	if subject.Id == current.Id {
		return renderError(403, "You cannot delete yourself.")
	}

	if subject.Deleted != nil {
		return renderError(409, "This user has already been deleted. Show some mercy.")
	}

	data := &userFormData{layoutData: NewLayoutData("Delete User", "users", current, x.GetToken())}
	data.fromUser(subject)

	err = subject.Delete()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogUserDeleted(current.Id, subject.Id)

	return redirect(302, "/users")
}

func setupUsersCtrl(app *martini.ClassicMartini) {
	app.Group("/users", func(r martini.Router) {
		app.Get("", usersIndexAction)
		app.Get("/add", usersAddAction)
		app.Post("", csrf.Validate, usersCreateAction)
		app.Get("/:id", usersEditAction)
		app.Put("/:id", csrf.Validate, usersUpdateAction)
		app.Delete("/:id", csrf.Validate, usersDeleteAction)
		app.Get("/:id/delete", usersDeleteConfirmAction)
	}, sessionauth.LoginRequired)
}
