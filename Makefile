.DEFAULT_GOAL := help

PROJECT_NAME := BETALOTEST AUTH

.PHONY: help
help:
	@echo "------------------------------------------------------------------------"
	@echo "${PROJECT_NAME}"
	@echo "------------------------------------------------------------------------"
	@grep -E '^[a-zA-Z0-9_/%\-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## start test container
	@docker-compose up --build test
	@docker-compose rm -fsv test

.PHONY: db/up
db/up: ## start database container
	@docker-compose up -d mongodb

.PHONY: db/stop
db/stop: ## stop and remove db container
	@docker-compose rm -fsv mongodb

.PHONY: db/cli
db/cli: ## enter in db cli mode
	@docker exec -it auth-db mongo admin

.PHONY: server/up
server/up: ## start auth server container
	@docker-compose up -d --build server

.PHONY: server/stop
server/stop: ## stop and remove auth server container
	@docker-compose rm -fsv server

.PHONY: auth/up
auth/up: ## start auth server behind reverse proxy
	@docker-compose up -d --build nginx

.PHONY: auth/stop
auth/stop: ## stop and remove auth service
	@docker-compose rm -fsv nginx
