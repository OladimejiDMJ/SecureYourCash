# FLASK USER AUTH WITH JSON WEB TOKEN

## Install dependencies

`pip install -r requirements.txt`

## To run tests

`pytest`

## To run API [Ubuntu]

Serving app with Gunicorn

`gunicorn --config gunicorn_config.py wsgi:app`

## ENDPOINTS

### Homepage

- endpoint: '/'
- method: GET

NOTE: auth_token should be in header. "Bearer +auth_token"

### Signup

- endpoint: '/signup'
- method: POST
- data: { "email":"xxxxxx", "password":"xxxxxx"}

### Login

- endpoint: '/login'
- method: POST
- data: { "email":"xxxxxx", "password":"xxxxxx"}
