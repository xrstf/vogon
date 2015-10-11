package main

import (
	"fmt"
	"net/http"

	"github.com/go-martini/martini"
	"github.com/jmoiron/sqlx"
)

func deliverSecretAction(params martini.Params, req *http.Request, db *sqlx.Tx) response {
	accessLog := NewAccessLog(db)

	// try to resolve the consumer
	consumerId := DecodeConsumerIdentifier(params["consumer"])
	consumer := findConsumer(consumerId, db)

	// try to resolve the secret (do not load the secret's content just yet)
	secret := findSecretBySlug(params["secret"], false, db)

	// stop if either of the two is not found
	if consumer == nil || secret == nil {
		accessLog.LogNotFound(consumer, secret, req)

		return newResponse(404, "Not Found.")
	}

	accessGranted := consumer.Enabled && !consumer.Deleted

	// check all restrictions
	contexts := make(map[string]interface{})
	restrictionsOkay := true

	for _, restriction := range consumer.GetRestrictions(true) {
		if !restriction.Enabled {
			continue
		}

		rType := restriction.Type

		okay, rContext := restriction.Check(req)
		restrictionsOkay = restrictionsOkay && okay

		fmt.Printf("rc = %+v\n", rContext)

		// remember the context if there was one
		if rContext != nil {
			contexts[rType] = rContext
		}
	}

	accessGranted = accessGranted && restrictionsOkay

	status := 200

	if !accessGranted {
		status = 403
	}

	// log the access [attempt]
	accessLog.LogAccess(consumer, secret, req, status, contexts)

	// no access => go away
	if !accessGranted {
		return newResponse(403, "Nope.")
	}

	// finally load the secret with its body
	secret = findSecret(secret.Id, true, db)

	decrypted, err := Decrypt(secret.Secret)
	if err != nil {
		return newResponse(500, "Nope.")
	}

	return newResponse(200, string(decrypted))
}

func setupDeliveryCtrl(app *martini.ClassicMartini) {
	app.Get("/get/:consumer/:secret", deliverSecretAction)
	app.Post("/get/:consumer/:secret", deliverSecretAction)
}
