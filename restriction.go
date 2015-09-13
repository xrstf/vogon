package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

// RestrictionHandler is an interface that represents a restriction implementation.
type RestrictionHandler interface {
	GetIdentifier() string
	GetNullContext() interface{}
	IsNullContext(interface{}) bool
	SerializeForm(*http.Request, bool, interface{}) (interface{}, error)
	CheckAccess(*http.Request, interface{}) (bool, interface{})
}

// Restriction represents a configured restriction for a consumer, stored in the database.
type Restriction struct {
	ConsumerId int      `db:"consumer_id"`
	Type       string   `db:"type"`
	Context    *Context `db:"context"`
	Enabled    bool     `db:"enabled"`
	_db        *sqlx.Tx
}

func findRestriction(consumerId int, rtype string, loadContext bool, db *sqlx.Tx) *Restriction {
	restriction := &Restriction{}
	restriction._db = db

	contextCol := ""

	if loadContext {
		contextCol = ", `context`"
	}

	db.Get(restriction, "SELECT `consumer_id`, `type`"+contextCol+", `enabled` FROM `restriction` WHERE `consumer_id` = ? AND `type` = ?", consumerId, rtype)
	if restriction.ConsumerId == 0 {
		return nil
	}

	return restriction
}

func findRestrictionsByConsumer(consumerId int, loadContext bool, db *sqlx.Tx) []Restriction {
	list := make([]Restriction, 0)
	contextCol := ""

	if loadContext {
		contextCol = ", `context`"
	}

	db.Select(&list, "SELECT `consumer_id`, `type`"+contextCol+", `enabled` FROM `restriction` WHERE `consumer_id` = ?", consumerId)

	for i := range list {
		list[i]._db = db
	}

	return list
}

func (r *Restriction) Save() error {
	if r.IsEmpty() {
		_, err := r._db.Exec(
			"DELETE FROM `restriction` WHERE `consumer_id` = ? AND `type` = ?",
			r.ConsumerId, r.Type,
		)

		if err != nil {
			return err
		}
	} else {
		_, err := r._db.Exec(
			"REPLACE INTO `restriction` (`consumer_id`, `type`, `context`, `enabled`) VALUES (?,?,?,?)",
			r.ConsumerId, r.Type, []byte(*r.Context), r.Enabled,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Restriction) Delete() error {
	_, err := r._db.Exec("DELETE FROM `restriction` WHERE `consumer_id` = ? AND `type` = ?", r.ConsumerId, r.Type)
	if err != nil {
		return err
	}

	return nil
}

func (r *Restriction) GetHandler() RestrictionHandler {
	handler, ok := restrictionHandlers[r.Type]
	if !ok {
		panic("Restriction for unknown type '" + r.Type + "' found.")
	}

	return handler
}

func (r *Restriction) UnpackContext() interface{} {
	context := r.GetHandler().GetNullContext()

	if r.Context != nil {
		r.Context.Unpack(&context)
	}

	return context
}

func (r *Restriction) IsEmpty() bool {
	if r.Enabled {
		return false
	}

	handler := r.GetHandler()
	context := r.UnpackContext()

	return handler.IsNullContext(context)
}

func (r *Restriction) Check(request *http.Request) (bool, interface{}) {
	handler := r.GetHandler()
	context := r.UnpackContext()

	return handler.CheckAccess(request, context)
}
