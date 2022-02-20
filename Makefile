all:current run

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./kuafu-linux ./*.go

current:
	go build -o ./kuafu ./main.go  ./config.go ./httpHandlers.go

run:
	sh ./test.sh
	
build:
	go build -o ./wujing ./main.go

github:
	cp *.go ../kuf/
	cp env.example ../kuf/
	cp ./*.md ../kuf/
	cp go.* ../kuf/
