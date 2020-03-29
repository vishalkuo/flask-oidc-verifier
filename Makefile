
.PHONY build-dist:
build-dist:
	python3 setup.py sdist bdist_wheel


publish:
	python3 -m twine upload dist/*
