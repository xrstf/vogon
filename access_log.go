package main

import "fmt"
import "github.com/jmoiron/sqlx"

type AccessLogEntry struct {
	Id          int    `db:"id"`
	Secret      int    `db:"secret_id"`
	Consumer    int    `db:"consumer_id"`
	RequestedAt string `db:"requested_at"`
	OriginIp    string `db:"origin_ip"`
}

type AccessLog interface {
	Find(int, int) []AccessLogEntry
	Count(int, int) int
}

type accessLogStruct struct {
	db *sqlx.Tx
}

func NewAccessLog(db *sqlx.Tx) AccessLog {
	return &accessLogStruct{db}
}

func (a *accessLogStruct) Find(secretId int, consumerId int) []AccessLogEntry {
	list := make([]AccessLogEntry, 0)
	where := a.buildWhereStatement(secretId, consumerId)

	a.db.Select(&list, "SELECT `id`, `secret_id`, `consumer_id`, `requested_at`, `origin_ip` FROM `access_log` WHERE "+where+" ORDER BY id DESC")

	return list
}

func (a *accessLogStruct) Count(secretId int, consumerId int) int {
	count := 0
	where := a.buildWhereStatement(secretId, consumerId)

	a.db.Get(&count, "SELECT COUNT(*) AS `c` FROM `access_log` WHERE "+where)

	return count
}

func (a *accessLogStruct) buildWhereStatement(secretId int, consumerId int) string {
	where := "1"

	if secretId > 0 {
		where += fmt.Sprintf(" AND `secret_id` = %d", secretId)
	}

	if consumerId > 0 {
		where += fmt.Sprintf(" AND `consumer_id` = %d", consumerId)
	}

	return where
}
