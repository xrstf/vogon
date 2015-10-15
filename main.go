package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
	"github.com/martini-contrib/gzip"
	"github.com/martini-contrib/method"
)

const TestString = "Umse ♪"

var templateManager *TemplateManager
var restrictionHandlers map[string]RestrictionHandler
var config *configuration
var sessions *SessionMiddleware

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

	// connect to database
	database, err := sqlx.Connect("mysql", config.Database.Source)
	if err != nil {
		kingpin.FatalUsage(err.Error())
	}

	validateMasterPassword(database)

	// init restriction handlers
	restrictionHandlers = make(map[string]RestrictionHandler)
	addRestrictionHandler(ApiKeyRestriction{})
	addRestrictionHandler(TlsCertRestriction{})
	addRestrictionHandler(OriginIpRestriction{})
	addRestrictionHandler(DateRestriction{})
	addRestrictionHandler(TimeRestriction{})
	addRestrictionHandler(FileRestriction{})
	addRestrictionHandler(HitLimitRestriction{})
	addRestrictionHandler(ThrottleRestriction{})

	// init templates
	templateManager = NewTemplateManager("templates")

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

	// setup session and CSRF support

	duration, err := time.ParseDuration(config.Session.Lifetime)
	if err != nil {
		log.Fatal("Invalid session lifetime configured: " + err.Error())
	}

	sessions = NewSessionMiddleware(cookieOptions{
		Name:     config.Session.CookieName,
		MaxAge:   duration,
		HttpOnly: true,
		Secure:   config.Session.Secure,
	})

	sessions.Setup(m)

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
	setupProfileCtrl(martini)
	setupLoginCtrl(martini)
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

type dbConfig struct {
	Key   string `db:"key"`
	Value []byte `db:"value"`
}

func validateMasterPassword(db *sqlx.DB) {
	c := dbConfig{}

	db.Get(&c, "SELECT `key`, `value` FROM `config` WHERE `key` = 'teststring'")

	if c.Key == "" {
		panic("Could not read the teststring from the config table. Your database is broken.")
	}

	// not yet initialized, so store the ciphertext
	if len(c.Value) == 0 {
		ciphertext, err := Encrypt([]byte(TestString))
		if err != nil {
			panic(err)
		}

		_, err = db.Exec("UPDATE `config` SET `value` = ? WHERE `key` = ?", ciphertext, c.Key)
		if err != nil {
			panic("Could not write initial password marker: " + err.Error())
		}
	} else {
		plaintext, err := Decrypt(c.Value)
		if err != nil {
			panic("The configured password is not usable for the configured database.")
		}

		// this should never happen: a wrong password should always yield an error in Decrypt()
		if TestString != string(plaintext) {
			panic("The configured password is not usable for the configured database.")
		}
	}
}
