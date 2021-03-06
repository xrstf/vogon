Raziel - Managing Secrets in Build Processes
============================================

This application can be used to have one central place to manage secrets like passwords,
private keys or certificates that are used in automated build processes (think of things
like Jenkins build jobs that need to embed a TLS certificate in a Docker image). Access
to those secrets happens via HTTPS.

For this, users can create secrets and consumers. Consumers allow automated access,
given certain conditions are met (like an API key, a certain day of the week or a specific
origin IP).

Secrets are stored in an encrypted fashion in a MariaDB database.

All access (attempts) and changes to secrets are logged in access and audit logs.

Build from Source
-----------------

You will need a recent Go compiler, at least version 1.4.

```
go get github.com/xrstf/raziel
cd $GOPATH/src/github.com/xrstf/raziel
make
```

Installation
------------

Create a TLS certificate if you don't have one. If you are only playing around, you can generate
your own using Go's TLS package:

    go run $GOROOT/src/crypto/tls/generate_cert.go --host localhost

Copy the ``config.json.dist`` and adjust it accordingly.

Now go ahead and initialize your database by executing the ``resources/schema.sql``.

Then, run Raziel:

    ./raziel --config myconfig.json
