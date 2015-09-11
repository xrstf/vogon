package main

import _ "github.com/go-sql-driver/mysql"
import "github.com/jmoiron/sqlx"

type Database struct {
	db *sqlx.DB
}

func NewDatabase() *Database {
	return &Database{}
}

func (self *Database) Connect(dsn string) error {
	db, err := sqlx.Connect("mysql", dsn)
	if err != nil {
		return err
	}

	self.db = db

	return nil
}
