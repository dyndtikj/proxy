all: build run

build:
	go build cmd/bin/main.go
	mv main cmd/bin/run/main

run_bin:
	./cmd/bin/run/main

build_and_run:
	go run cmd/bin/main.go

run:
	docker-compose up --build mongo


