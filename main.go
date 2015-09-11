package main

import "github.com/go-martini/martini"
import "github.com/martini-contrib/method"
import "github.com/martini-contrib/csrf"
import "github.com/martini-contrib/gzip"
import "github.com/martini-contrib/render"
import "github.com/martini-contrib/sessions"
import "github.com/martini-contrib/sessionauth"
import "github.com/jmoiron/sqlx"
import "net/http"
import "strconv"

var templateManager *TemplateManager
var restrictionHandlers map[string]RestrictionHandler
var authenticationHandlers map[string]AuthenticationHandler

func main() {
	templateManager = NewTemplateManager("templates")

	database, err := sqlx.Connect("mysql", "develop:develop@/raziel")
	if err != nil {
		panic("nop")
	}

	restrictionHandlers = make(map[string]RestrictionHandler)
	addRestrictionHandler(OriginIpRestriction{})
	addRestrictionHandler(DateRestriction{})
	addRestrictionHandler(TimeRestriction{})
	addRestrictionHandler(FileRestriction{})
	addRestrictionHandler(HitLimitRestriction{})
	addRestrictionHandler(ThrottleRestriction{})

	authenticationHandlers = make(map[string]AuthenticationHandler)
	addAuthenticationHandler(ApiKeyAuthentication{})
	addAuthenticationHandler(TlsCertAuthentication{})

	// setup basic Martini server

	// martini.Env = martini.Prod

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

	store := sessions.NewCookieStore([]byte("secret123"))
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
		Secret:     "token123",
		SessionKey: sessionauth.SessionKey,
		// Custom error response.
		ErrorFunc: func(w http.ResponseWriter) {
			http.Error(w, "CSRF token validation failed", http.StatusBadRequest)
		},
	}))

	// re-compile all templates on each hit

	m.Use(func() {
		templateManager.Init()
	})

	// use a custom return handler to make our mini response structs possible
	// (this overwrites the existing handler)
	m.Map(newReturnHandler())

	r := martini.NewRouter()
	m.MapTo(r, (*martini.Routes)(nil))
	m.Action(r.Handle)

	martini := &martini.ClassicMartini{m, r}
	setupOverviewCtrl(martini)
	setupSecretsCtrl(martini)
	setupUsersCtrl(martini)
	setupConsumersCtrl(martini)
	setupAuditLogCtrl(martini)

	martini.Run()
}

func addRestrictionHandler(handler RestrictionHandler) {
	restrictionHandlers[handler.GetIdentifier()] = handler
}

func addAuthenticationHandler(handler AuthenticationHandler) {
	authenticationHandlers[handler.GetIdentifier()] = handler
}
