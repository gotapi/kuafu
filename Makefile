all:current run

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./kuafu-linux-amd64 ./src/

current:
	go build -o ./kuafu ./src/

run:
	./kuafu -config ./etc/main.toml
