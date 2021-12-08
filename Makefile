all:current run

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./wujing ./main.go 

current:
	go build -o ./wujing ./main.go 

run:
	sh ./test.sh
