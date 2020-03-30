PROJ=flask-oidc-verifier

.PHONY build-dist:
build-dist:
	python3 setup.py sdist bdist_wheel

.PHONY publish:
publish:
	python3 -m twine upload dist/*

.PHONY startredis:
startredis:
	docker-compose -p $(PROJ) -f docker/docker-compose.yml up -d --no-recreate

.PHONY stopredis:
stopredis:
	docker-compose -p $(PROJ) -f docker/docker-compose.yml down

.PHONY typecheck:
typecheck:
	mypy flask_oidc_verifier tests
