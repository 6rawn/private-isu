.PHONY: up
up:
	docker compose up -d

.PHONY: down
down:
	docker compose down

.PHONY: restart
restart:
	docker compose down; docker compose up -d

.PHONY: build
build:
	docker compose build

.PHONY: clean
clean:
	docker compose down --rmi all

.PHONY: log
log:
	docker compose logs -f

.PHONY: reset-logs
reset-logs:
	mv ./logs/nginx/access.log ./logs/nginx/access.log.$(shell date +%Y%m%d-%H%M%S) | : 
	mv ./logs/mysql/mysql-slow.log ./logs/mysql/mysql-slow.log.$(shell date +%Y%m%d-%H%M%S) | : 
	@make restart


.PHONY: alp
alp:
	# ./alp json --file logs/nginx/access.log 
	./alp json --file logs/nginx/access.log -o count,method,uri,min,avg,max

.PHONY: ab
ab:
	ab -c 4 -t 30 http://localhost/

.PHONY: benchmarker
benchmarker:
	docker run --network host -i private-isu-benchmarker /opt/go/bin/benchmarker -t http://172.17.0.1 -u /opt/go/userdata

.PHONY: mysqldumpslow
mysqldumpslow:
	mysqldumpslow ./logs/mysql/mysql-slow.log

.PHONY: dstat
dstat:
	if [[ "`uname -a`" == *"Linus"* ]]; then dstat --cpu; fi

.PHONY: stats
stats:
	docker stats

.PHONY: pt-query-digest
pt-query-digest:
	./pt-query-digest ./logs/mysql/mysql-slow.log | tee digest_$(shell date +%Y%m%d%H%M).txt

.PHONY: query-digester
query-digester:
	./query-digester


.PHONY: requirements
requirements:
	./install.sh

