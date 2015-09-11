package main

import "github.com/go-martini/martini"
import "github.com/martini-contrib/csrf"
import "github.com/martini-contrib/sessionauth"
import "github.com/jmoiron/sqlx"
import "github.com/speps/go-hashids"
import "net/http"
import "strings"
import "strconv"
import "fmt"
import "log"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Consumer model
////////////////////////////////////////////////////////////////////////////////////////////////////

type Consumer struct {
	Id         int     `db:"id"`
	Name       string  `db:"name"`
	CreatedAt  string  `db:"created_at"`
	UpdatedAt  *string `db:"updated_at"`
	CreatedBy  int     `db:"created_by"`
	UpdatedBy  *int    `db:"updated_by"`
	Enabled    bool    `db:"enabled"`
	Deleted    bool    `db:"deleted"`
	InfoToken  *string `db:"info_token"`
	LastSeenAt *string `db:"last_seen"` // virtual, only for list view
	_db        *sqlx.Tx
}

func findAllConsumers(db *sqlx.Tx) []Consumer {
	list := make([]Consumer, 0)
	db.Select(&list, "SELECT `id`, `name`, `created_at`, `updated_at`, `created_by`, `updated_by`, `enabled`, `deleted`, `info_token` FROM `consumer` c WHERE `deleted` = 0 ORDER BY `name`")

	for i, _ := range list {
		list[i]._db = db
	}

	return list
}

func findConsumer(id int, db *sqlx.Tx) *Consumer {
	consumer := &Consumer{}
	consumer._db = db

	db.Get(consumer, "SELECT `id`, `name`, `created_at`, `updated_at`, `created_by`, `updated_by`, `enabled`, `deleted`, `info_token` FROM `consumer` WHERE `id` = ?", id)
	if consumer.Id == 0 {
		return nil
	}

	return consumer
}

func (c *Consumer) Save() error {
	if c.Id <= 0 {
		result, err := c._db.Exec(
			"INSERT INTO `consumer` (`name`, `created_at`, `created_by`, `enabled`, `deleted`, `info_token`) VALUES (?,NOW(),?,?,?,?)",
			c.Name, c.CreatedBy, c.Enabled, c.Deleted, c.InfoToken,
		)

		if err != nil {
			return err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return err
		}

		c.Id = int(id)
	} else {
		// deleted=0 is to guarantee that we do not modify deleted consumers
		_, err := c._db.Exec(
			"UPDATE `consumer` SET `name` = ?, `updated_at` = NOW(), `updated_by` = ?, `enabled` = ?, `deleted` = ?, `info_token` = ? WHERE `id` = ? AND `deleted` = 0",
			c.Name, c.UpdatedBy, c.Enabled, c.Deleted, c.InfoToken, c.Id,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Consumer) Delete() error {
	_, err := c._db.Exec("UPDATE `consumer` SET `deleted` = 1 WHERE `id` = ?", c.Id)
	if err != nil {
		return err
	}

	return nil
}

func (c *Consumer) GetIdentifier() string {
	hd := hashids.NewData()
	hd.Salt = "this is my salt"
	hd.MinLength = 15
	h := hashids.NewWithData(hd)

	hash, _ := h.Encode([]int{c.Id})

	return hash
}

func (c *Consumer) GetCreator() *User {
	return findUser(c.CreatedBy, false, c._db)
}

func (c *Consumer) GetUpdater() *User {
	if c.UpdatedBy == nil {
		return nil
	}

	return findUser(*c.UpdatedBy, false, c._db)
}

func (c *Consumer) GetAuthentication(loadContext bool) *Authentication {
	return findAuthenticationByConsumer(c.Id, loadContext, c._db)
}

func (c *Consumer) GetRequirements(loadContext bool) []Restriction {
	return findRestrictionsByConsumer(c.Id, loadContext, c._db)
}

func (c *Consumer) GetSecrets(loadSecrets bool) []Secret {
	secrets := make([]Secret, 0)
	secretCol := ""

	if loadSecrets {
		secretCol = ", `secret`"
	}

	c._db.Select(&secrets, "SELECT `id`, `slug`, `name`, `created_at`, `created_by`, `updated_at`, `updated_by`"+secretCol+" FROM `secret` WHERE `id` IN (SELECT `secret_id` FROM `consumer_secret` WHERE `consumer_id` = ?) ORDER BY `name`", c.Id)

	for i, _ := range secrets {
		secrets[i]._db = c._db
	}

	return secrets
}

func (c *Consumer) WriteSecrets(secrets []consumerSecret) error {
	_, err := c._db.Exec("DELETE FROM `consumer_secret` WHERE `consumer_id` = ?", c.Id)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		if secret.Checked {
			_, err := c._db.Exec("INSERT INTO `consumer_secret` (`consumer_id`, `secret_id`) VALUES (?,?)", c.Id, secret.Id)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Consumer) WriteRestrictions(restrictons map[string]consumerRestriction) error {
	for rtype, restriction := range restrictons {
		r := &Restriction{
			ConsumerId: c.Id,
			Type:       rtype,
			Context:    PackContext(restriction.Context),
			Enabled:    restriction.Enabled,
			_db:        c._db,
		}

		err := r.Save()
		if err != nil {
			return err
		}
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP Handlers
////////////////////////////////////////////////////////////////////////////////////////////////////

type emptyStruct struct{}

type consumerListData struct {
	layoutData

	Consumers []Consumer
}

type consumerSecret struct {
	Id      int    `db:"id"`
	Name    string `db:"name"`
	Slug    string `db:"slug"`
	Checked bool   `db:"checked"`
}

type consumerRestriction struct {
	Type    string
	Context interface{}
	Enabled bool
	Error   string
}

func (cr *consumerRestriction) GetHandler() RestrictionHandler {
	handler, ok := restrictionHandlers[cr.Type]
	if !ok {
		return nil
	}

	return handler
}

func (cr *consumerRestriction) IsNullContext() bool {
	handler := cr.GetHandler()
	if handler == nil {
		return false
	}

	return handler.IsNullContext(cr.Context)
}

type consumerFormData struct {
	layoutData

	Consumer       int
	Name           string
	NameError      string
	Enabled        bool
	InfoToken      *string
	InfoTokenError string
	OtherError     string
	Secrets        []consumerSecret
	AuthType       string
	AuthTypeError  string
	AuthInfo       interface{}
	AuthErrors     map[string]string
	Restrictions   map[string]consumerRestriction
}

func newConsumerFormData(layout layoutData) consumerFormData {
	data := consumerFormData{layoutData: layout}

	data.Secrets = make([]consumerSecret, 0)
	data.AuthErrors = make(map[string]string)
	data.Restrictions = make(map[string]consumerRestriction)

	return data
}

func (data *consumerFormData) primeRestrictions() {
	data.Restrictions = make(map[string]consumerRestriction)

	for identifier, handler := range restrictionHandlers {
		data.Restrictions[identifier] = consumerRestriction{identifier, handler.GetNullContext(), false, ""}
	}
}

func (data *consumerFormData) primeSecrets(db *sqlx.Tx) {
	secrets := findAllSecrets(false, db)

	data.Secrets = make([]consumerSecret, len(secrets))

	for idx, secret := range secrets {
		data.Secrets[idx].Id = secret.Id
		data.Secrets[idx].Name = secret.Name
		data.Secrets[idx].Slug = secret.Slug
		data.Secrets[idx].Checked = false
	}
}

func (data *consumerFormData) fromConsumer(c *Consumer) {
	data.Consumer = c.Id
	data.Name = c.Name
	data.Enabled = c.Enabled
	data.InfoToken = c.InfoToken
	data.Secrets = make([]consumerSecret, 0)
	data.AuthType = ""
	data.AuthInfo = nil

	// load authentication information
	auth := c.GetAuthentication(true)
	if auth != nil {
		data.AuthType = auth.Type
		data.AuthInfo = auth.UnpackContext()
	}

	// load secrets
	c._db.Select(&data.Secrets, "SELECT s.id, s.name, s.slug, IF(cs.secret_id IS NULL, 0, 1) AS checked FROM secret s LEFT JOIN consumer_secret cs ON s.id = cs.secret_id AND cs.consumer_id = ? ORDER BY s.name", c.Id)

	// load restrictions (and overwrite the dummy values from primeRestrictions)
	for _, restriction := range c.GetRequirements(true) {
		data.Restrictions[restriction.Type] = consumerRestriction{restriction.Type, restriction.UnpackContext(), restriction.Enabled, ""}
	}
}

func (data *consumerFormData) serializeForm(req *http.Request) bool {
	okay := true
	name := strings.TrimSpace(req.FormValue("name"))
	authType := req.FormValue("authentication")
	enabled := req.FormValue("enabled") == "1"
	infoToken := req.FormValue("info_token")

	data.Enabled = enabled

	if len(name) > 0 {
		data.Name = name
	} else {
		data.NameError = "The name cannot be empty."
		okay = false
	}

	if len(infoToken) > 0 {
		data.InfoToken = &infoToken
	}

	for idx, consumerSecret := range data.Secrets {
		data.Secrets[idx].Checked = req.FormValue(fmt.Sprintf("secret_%d", consumerSecret.Id)) == "1"
	}

	// serialize authentication information
	authHandler, okay := authenticationHandlers[authType]
	if !okay {
		data.AuthTypeError = "Invalid authentication selected."
		okay = false
	} else {
		data.AuthType = authType

		var err error
		var authCtx interface{}

		// if we are using the same auth type as before, we can hand the current context to the handler
		if authType == data.AuthType {
			authCtx, err = authHandler.SerializeForm(req, data.AuthInfo)
		} else {
			authCtx, err = authHandler.SerializeForm(req, nil)
		}

		if err != nil {
			data.AuthErrors[authType] = err.Error()
			okay = false
		}

		if authCtx == nil {
			authCtx = authHandler.GetNullContext()
		}

		data.AuthInfo = authCtx
	}

	for rtype, consumerRestriction := range data.Restrictions {
		consumerRestriction.Enabled = req.FormValue("restriction_"+rtype) == "1"

		handler, ok := restrictionHandlers[rtype]
		if !ok {
			log.Println("Warning: restriction found for unknown type '" + rtype + "'.")
			continue
		}

		resultCtx, err := handler.SerializeForm(req, consumerRestriction.Enabled, consumerRestriction.Context)
		if err != nil {
			consumerRestriction.Error = err.Error()
			okay = false
		}

		// always use the new context, if we got one
		if resultCtx != nil {
			consumerRestriction.Context = resultCtx
		}

		// set the struct we just read; this is because mapvar["key"].Field is not allowed in Go
		data.Restrictions[rtype] = consumerRestriction
	}

	return okay
}

func consumersIndexAction(user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := &consumerListData{NewLayoutData("Consumers", "consumers", user, x.GetToken()), make([]Consumer, 0)}
	lastSeen := "(SELECT a.`requested_at` FROM `access_log` a WHERE a.`consumer_id` = c.`id` ORDER BY `id` DESC LIMIT 1) AS `last_seen`"

	// find consumers (do not even select the consumer itself, we don't need it)
	db.Select(
		&data.Consumers,
		"SELECT `id`, `name`, `created_at`, `updated_at`, `created_by`, `updated_by`, `enabled`, `info_token`, "+lastSeen+" FROM `consumer` c WHERE `deleted` = 0 ORDER BY `name`",
	)

	for i, _ := range data.Consumers {
		data.Consumers[i]._db = db
	}

	return renderTemplate(200, "consumers/index", data)
}

func consumersAddAction(user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := newConsumerFormData(NewLayoutData("Add Consumer", "consumers", user, x.GetToken()))
	data.primeRestrictions()
	data.primeSecrets(db)

	// set some sane defaults
	data.Enabled = true
	data.AuthType = "api_key"
	data.AuthInfo = apiKeyContext{""}

	return renderTemplate(200, "consumers/form", data)
}

func consumersCreateAction(req *http.Request, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	data := newConsumerFormData(NewLayoutData("Add Consumer", "consumers", user, x.GetToken()))
	data.primeRestrictions()
	data.primeSecrets(db)

	// evaluate the form
	okay := data.serializeForm(req)

	if !okay {
		return renderTemplate(400, "consumers/form", data)
	}

	// create the consumer
	newConsumer := &Consumer{
		Id:        -1,
		Name:      data.Name,
		Enabled:   data.Enabled,
		InfoToken: data.InfoToken,
		CreatedBy: user.Id,
		_db:       db,
	}

	err := newConsumer.Save()
	if err != nil {
		panic(err)
	}

	// create links to the allowed secrets
	err = newConsumer.WriteSecrets(data.Secrets)
	if err != nil {
		panic(err)
	}

	// create the authentication info
	auth := &Authentication{
		ConsumerId: newConsumer.Id,
		Type:       data.AuthType,
		Context:    PackContext(data.AuthInfo),
		_db:        db,
	}

	err = auth.Save()
	if err != nil {
		panic(err)
	}

	// write all restrictions
	err = newConsumer.WriteRestrictions(data.Restrictions)
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogConsumerCreated(newConsumer.Id, user.Id)

	return redirect(302, "/consumers")
}

func consumersEditAction(params martini.Params, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	consumer := findConsumer(id, db)
	if consumer == nil {
		return renderError(404, "Consumer could not be found.")
	}

	data := newConsumerFormData(NewLayoutData("Edit Consumer", "consumers", user, x.GetToken()))
	data.primeRestrictions()
	data.primeSecrets(db)
	data.fromConsumer(consumer)

	return renderTemplate(200, "consumers/form", data)
}

func consumersUpdateAction(params martini.Params, req *http.Request, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	consumer := findConsumer(id, db)
	if consumer == nil {
		return renderError(404, "Consumer could not be found.")
	}

	// initialize our data object
	data := newConsumerFormData(NewLayoutData("Edit Consumer", "consumers", user, x.GetToken()))
	data.primeRestrictions()
	data.primeSecrets(db)
	data.fromConsumer(consumer)

	// evaluate the form
	okay := data.serializeForm(req)

	if !okay {
		return renderTemplate(400, "consumers/form", data)
	}

	// update the consumer
	consumer.Name = data.Name
	consumer.Enabled = data.Enabled
	consumer.InfoToken = data.InfoToken
	consumer.UpdatedBy = &user.Id

	err = consumer.Save()
	if err != nil {
		panic(err)
	}

	// create links to the allowed secrets
	err = consumer.WriteSecrets(data.Secrets)
	if err != nil {
		panic(err)
	}

	// update authentication
	auth := consumer.GetAuthentication(false)
	if auth == nil { // this should never happen
		auth = &Authentication{ConsumerId: consumer.Id, _db: db}
	}

	auth.Type = data.AuthType
	auth.Context = PackContext(data.AuthInfo)

	err = auth.Save()
	if err != nil {
		panic(err)
	}

	// write all restrictions
	err = consumer.WriteRestrictions(data.Restrictions)
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogConsumerUpdated(consumer.Id, user.Id)

	return redirect(302, "/consumers")
}

func consumersDeleteConfirmAction(params martini.Params, user *User, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	consumer := findConsumer(id, db)
	if consumer == nil {
		return renderError(404, "Consumer could not be found.")
	}

	data := newConsumerFormData(NewLayoutData("Delete Consumer", "consumers", user, x.GetToken()))
	data.fromConsumer(consumer)

	return renderTemplate(200, "consumers/confirmation", data)
}

func consumersDeleteAction(params martini.Params, user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	consumer := findConsumer(id, db)
	if consumer == nil {
		return renderError(404, "Consumer could not be found.")
	}

	data := newConsumerFormData(NewLayoutData("Delete Consumer", "consumers", user, x.GetToken()))
	data.fromConsumer(consumer)

	err = consumer.Delete()
	if err != nil {
		panic(err)
	}

	auditLog := NewAuditLog(db, req)
	auditLog.LogConsumerDeleted(consumer.Id, user.Id)

	return redirect(302, "/consumers")
}

type consumerUrlsData struct {
	layoutData

	Consumer *Consumer
	Secrets  []Secret
}

func newConsumerUrlsData(layout layoutData) consumerUrlsData {
	data := consumerUrlsData{layoutData: layout}
	data.Secrets = make([]Secret, 0)

	return data
}

func consumersUrlsAction(params martini.Params, user *User, req *http.Request, x csrf.CSRF, db *sqlx.Tx) response {
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		return renderError(400, "Invalid ID given.")
	}

	consumer := findConsumer(id, db)
	if consumer == nil {
		return renderError(404, "Consumer could not be found.")
	}

	data := newConsumerUrlsData(NewLayoutData("Consumer URLs", "consumers", user, x.GetToken()))
	data.Consumer = consumer
	data.Secrets = consumer.GetSecrets(false)

	return renderTemplate(200, "consumers/urls", data)
}

func setupConsumersCtrl(app *martini.ClassicMartini) {
	app.Group("/consumers", func(r martini.Router) {
		app.Get("", consumersIndexAction)
		app.Get("/add", consumersAddAction)
		app.Post("", csrf.Validate, consumersCreateAction)
		app.Get("/:id", consumersEditAction)
		app.Put("/:id", csrf.Validate, consumersUpdateAction)
		app.Delete("/:id", csrf.Validate, consumersDeleteAction)
		app.Get("/:id/delete", consumersDeleteConfirmAction)
		app.Get("/:id/urls", consumersUrlsAction)
	}, sessionauth.LoginRequired)
}
