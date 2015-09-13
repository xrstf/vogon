package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

// AuthenticationHandler is an interface that represents a restriction implementation.
type AuthenticationHandler interface {
	GetIdentifier() string
	GetNullContext() interface{}
	SerializeForm(*http.Request, interface{}) (interface{}, error)
	CheckAccess(*http.Request, interface{}) (bool, interface{})
}

type Authentication struct {
	ConsumerId int      `db:"consumer_id"`
	Type       string   `db:"type"`
	Context    *Context `db:"context"`
	_db        *sqlx.Tx
}

func findAuthenticationByConsumer(consumerId int, loadContext bool, db *sqlx.Tx) *Authentication {
	auth := &Authentication{}
	auth._db = db

	contextCol := ""

	if loadContext {
		contextCol = ", `context`"
	}

	db.Get(auth, "SELECT `consumer_id`, `type`"+contextCol+" FROM `authentication` WHERE `consumer_id` = ?", consumerId)
	if auth.ConsumerId == 0 {
		return nil
	}

	return auth
}

func (a *Authentication) Save() error {
	var err error

	// if the context wasn't fetched, don't attempt to update it
	if a.Context == nil {
		_, err = a._db.Exec(
			"REPLACE INTO `authentication` (`consumer_id`, `type`) VALUES (?,?)",
			a.ConsumerId, a.Type,
		)
	} else {
		_, err = a._db.Exec(
			"REPLACE INTO `authentication` (`consumer_id`, `type`, `context`) VALUES (?,?,?)",
			a.ConsumerId, a.Type, []byte(*a.Context),
		)
	}

	if err != nil {
		return err
	}

	return nil
}

func (a *Authentication) Delete() error {
	_, err := a._db.Exec("DELETE FROM `authentication` WHERE `consumer_id` = ?", a.ConsumerId)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authentication) GetHandler() AuthenticationHandler {
	handler, ok := authenticationHandlers[a.Type]
	if !ok {
		panic("Authentication for unknown type '" + a.Type + "' found.")
	}

	return handler
}

func (a *Authentication) UnpackContext() interface{} {
	handler := authenticationHandlers[a.Type]
	context := handler.GetNullContext()

	if a.Context != nil {
		a.Context.Unpack(&context)
	}

	return context
}

func (a *Authentication) Check(request *http.Request) (bool, interface{}) {
	handler := a.GetHandler()
	context := a.UnpackContext()

	return handler.CheckAccess(request, context)
}
