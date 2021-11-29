# solution to "syscall.Mprotect panic: permission denied" in Golang on macOS Catalina 10.15.x when using GoMonkey
# https://github.com/eisenxp/macos-golink-wrapper

go get ./...
go build ./...
go test ./... -tags runTests -gcflags=all=-l -cover