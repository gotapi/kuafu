all:current run

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./wujing-linux-64 ./main.go 

current:
	go build -o ./kuafu ./main.go  ./config.go ./httpHandlers.go

run:
	sh ./test.sh
	
build:
	go build -o ./wujing ./main.go

github:
	cp *.go ../kuafu/
	cp env.example ../kuafu/
	cp ./*.md ../kuafu/
	cp go.* ../kuafu/
