.PHONY: docker test

docker:
	docker build . -t christophetd/firepwned

test:
	python -m unittest discover test
