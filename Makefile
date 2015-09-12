default: fix
	go build -v

fix: *.go
	goimports -l -w .
	gofmt -l -w .

run: default
	./raziel.exe
