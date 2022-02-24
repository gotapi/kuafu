all:current run

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./kuafu-linux ./src/

current:
	go build -o ./kuafu ./src/

run:
	sh ./test.sh
