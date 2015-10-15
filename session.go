package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
)

type cookieOptions struct {
	Name     string
	MaxAge   time.Duration
	HttpOnly bool
	Secure   bool
}

type Session struct {
	ID        string
	User      int
	CsrfToken string
	Flashes   []string
	Expires   time.Time
}

func (s *Session) WriteCookie(options cookieOptions, response http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     options.Name,
		Value:    s.ID,
		Expires:  time.Now().Add(options.MaxAge),
		HttpOnly: options.HttpOnly,
		Secure:   options.Secure,
	}

	response.Header().Set("Set-Cookie", cookie.String())
}

func (s *Session) DeleteCookie(options cookieOptions, response http.ResponseWriter) {
	cookie := http.Cookie{
		Name:   options.Name,
		Value:  "-",
		MaxAge: -1,
	}

	response.Header().Set("Set-Cookie", cookie.String())
}

type sessionMap map[string]*Session

type SessionMiddleware struct {
	sessions sessionMap
	options  cookieOptions
}

func NewSessionMiddleware(options cookieOptions) *SessionMiddleware {
	return &SessionMiddleware{make(sessionMap), options}
}

func (m *SessionMiddleware) Setup(martini *martini.Martini) {
	martini.Use(m.ResolveSessionCookie)

	go m.cleanup()
}

func (m *SessionMiddleware) ResolveSessionCookie(r *http.Request, response http.ResponseWriter, c martini.Context, db *sqlx.Tx) {
	// find session cookie
	cookie, err := r.Cookie(m.options.Name)
	valid := false

	var sess *Session
	var user *User

	if err == nil {
		clientID := cookie.Value
		now := time.Now()

		// find session
		var okay bool
		sess, okay = m.sessions[clientID]

		if okay == true {
			if now.After(sess.Expires) { // session expired
				m.destroySession(sess)
			} else {
				// find associated user and check if they're deleted
				user = findUser(sess.User, false, db)
				valid = user != nil && user.Deleted == nil

				if valid {
					sess.Expires = now.Add(m.options.MaxAge)

					// refresh the cookie
					sess.WriteCookie(m.options, response)
				} else {
					m.destroySession(sess)
				}
			}
		}
	}

	if !valid {
		sess = &Session{"", 0, "", make([]string, 0), time.Now()}
		user = &User{}
	}

	c.Map(user)
	c.Map(sess)
	c.Map(m)
}

func (m *SessionMiddleware) RequireLogin(user *User, req *http.Request, res http.ResponseWriter) {
	if user.Id <= 0 || user.Deleted != nil {
		http.Redirect(res, req, "/login", 302)
	}
}

func (m *SessionMiddleware) RequireCsrfToken(session *Session, req *http.Request, res http.ResponseWriter) {
	if session == nil {
		http.Error(res, "Nope.", http.StatusUnauthorized)
		return
	}

	token := req.FormValue("_csrf")
	if token == "" {
		http.Error(res, "Nope.", http.StatusBadRequest)
		return
	}

	if token != session.CsrfToken {
		http.Error(res, "Nope.", http.StatusForbidden)
		return
	}
}

func (m *SessionMiddleware) StartSession(user *User, response http.ResponseWriter) (*Session, error) {
	session, err := m.newSession(user)
	if err != nil {
		return nil, err
	}

	session.WriteCookie(m.options, response)

	return session, nil
}

func (m *SessionMiddleware) newSession(user *User) (*Session, error) {
	expires := time.Now().Add(m.options.MaxAge)
	sess := Session{"", 0, "", make([]string, 0), expires}

	if user != nil {
		sess.User = user.Id
	}

	// create csrf token
	id, err := safeRandomString(64)
	if err != nil {
		return nil, err
	}

	sess.CsrfToken = id

	// create session id
	id, err = safeRandomString(64)
	if err != nil {
		return nil, err
	}

	sess.ID = id

	m.sessions[id] = &sess

	return &sess, nil
}

func (m *SessionMiddleware) EndSession(session *Session, response http.ResponseWriter) (*Session, error) {
	m.destroySession(session)
	session.DeleteCookie(m.options, response)

	return session, nil
}

func (m *SessionMiddleware) destroySession(session *Session) {
	delete(m.sessions, session.ID)
}

func (m *SessionMiddleware) cleanup() {
	for {
		now := time.Now()

		for _, sess := range m.sessions {
			if now.After(sess.Expires) {
				m.destroySession(sess)
			}
		}

		<-time.After(1 * time.Minute)
	}
}

func safeRandomString(length int) (string, error) {
	str := make([]byte, length)

	_, err := rand.Read(str)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(str), nil
}
