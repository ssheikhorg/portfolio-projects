install:
	python -m pip install --upgrade pip && \
	pip install -U -r requirements.txt

fmt:
	ruff format .