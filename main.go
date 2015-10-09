package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/alecthomas/kingpin"
	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/gzip"
	"github.com/martini-contrib/method"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessions"
)

var templateManager *TemplateManager
var restrictionHandlers map[string]RestrictionHandler
var config *configuration

var (
	password   = kingpin.Flag("password", "Encryption key in plain text (discouraged)").String()
	configFile = kingpin.Flag("config", "Configuration file to use").ExistingFile()
)

func main() {
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version("1.0").Author("Christoph Mewes")
	kingpin.CommandLine.Help = "HTTP application server to run the Raziel secret management"
	kingpin.Parse()

	if *configFile == "" {
		kingpin.FatalUsage("No configuration file (--config) given!")
	}

	// load config file
	err := loadConfigFile()
	if err != nil {
		kingpin.FatalUsage(err.Error())
	}

	// init templates
	templateManager = NewTemplateManager("templates")

	// connect to database
	database, err := sqlx.Connect("mysql", config.Database.Source)
	if err != nil {
		kingpin.FatalUsage(err.Error())
	}

	restrictionHandlers = make(map[string]RestrictionHandler)
	addRestrictionHandler(ApiKeyRestriction{})
	addRestrictionHandler(TlsCertRestriction{})
	addRestrictionHandler(OriginIpRestriction{})
	addRestrictionHandler(DateRestriction{})
	addRestrictionHandler(TimeRestriction{})
	addRestrictionHandler(FileRestriction{})
	addRestrictionHandler(HitLimitRestriction{})
	addRestrictionHandler(ThrottleRestriction{})

	// setup basic Martini server

	martini.Env = martini.Dev

	if config.Environment == "production" || config.Environment == "prod" {
		martini.Env = martini.Prod
	}

	m := martini.New()
	m.Use(martini.Logger())
	m.Use(gzip.All())
	m.Use(martini.Recovery())
	m.Use(martini.Static("www"))
	m.Use(method.Override())

	// force all handlers to run inside a transaction

	m.Use(func(c martini.Context) {
		tx := database.MustBegin()

		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
				panic(r)
			}
		}()

		c.Map(tx)
		c.Next()

		err := tx.Commit()
		if err != nil {
			panic(err)
		}
	})

	// initialize basic session support

	store := sessions.NewCookieStore([]byte(config.SessionKey))
	session := sessions.Sessions("my_session", store)

	m.Use(session)
	m.Use(func(s sessions.Session) {
		s.Options(sessions.Options{HttpOnly: true})
	})

	// initialize the authentication handler for the web UI

	m.Use(render.Renderer()) // TODO: ensure this doesnt do anything (i.e. doesn't load templates), because we only need it for the sessionauth middleware
	m.Use(func(s sessions.Session, c martini.Context, db *sqlx.Tx) {
		userId := s.Get(sessionauth.SessionKey)
		user := &User{}

		if userId != nil {
			id, ok := userId.(string)
			if ok {
				converted, err := strconv.Atoi(id)
				if err == nil {
					user = findUser(converted, true, db)
				}
			}
		}

		c.Map(user)
	})

	sessionauth.RedirectUrl = "/login"
	sessionauth.RedirectParam = "next"

	// Map the generic sessionauth.User interface to our User struct,
	// so controllers don't have to cast themselves.
	m.Use(func(u sessionauth.User, c martini.Context) {
		c.Map(u.(*User))
	})

	// initialize CSRF protection

	m.Use(csrf.Generate(&csrf.Options{
		Secret:     config.CsrfKey,
		SessionKey: sessionauth.SessionKey,
		// Custom error response.
		ErrorFunc: func(w http.ResponseWriter) {
			http.Error(w, "CSRF token validation failed", http.StatusBadRequest)
		},
	}))

	// re-compile all templates on each hit

	if martini.Env != martini.Prod {
		m.Use(func() {
			templateManager.Init()
		})
	}

	// use a custom return handler to make our mini response structs possible
	// (this overwrites the existing handler)
	m.Map(newReturnHandler())

	r := martini.NewRouter()
	m.MapTo(r, (*martini.Routes)(nil))
	m.Action(r.Handle)

	martini := &martini.ClassicMartini{m, r}
	setupDashboardCtrl(martini)
	setupSessionCtrl(martini)
	setupSecretsCtrl(martini)
	setupUsersCtrl(martini)
	setupConsumersCtrl(martini)
	setupAuditLogCtrl(martini)
	setupAccessLogCtrl(martini)
	setupDeliveryCtrl(martini)

	// setup our own http server and configure TLS
	srv := &http.Server{
		Addr:    config.Server.Listen,
		Handler: martini,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites(),
		},
	}

	log.Fatal(srv.ListenAndServeTLS(config.Server.Certificate, config.Server.PrivateKey))
}

func addRestrictionHandler(handler RestrictionHandler) {
	restrictionHandlers[handler.GetIdentifier()] = handler
}

func loadConfigFile() error {
	content, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return err
	}

	config = &configuration{}
	err = json.Unmarshal(content, &config)
	if err != nil {
		return err
	}

	return nil
}
