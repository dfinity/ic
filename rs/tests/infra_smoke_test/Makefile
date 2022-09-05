all:
	which pipenv || pip install pipenv
	if [ ! -f Pipfile ]; then pipenv --python 3.8 ; fi
	pipenv run pip install -r requirements.txt
	pipenv run python infra_smoke_test.py
