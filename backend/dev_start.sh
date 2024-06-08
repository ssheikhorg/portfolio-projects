#! /usr/bin/env sh

. /app/prestart.sh

uvicorn api.main:app --reload --host 0.0.0.0 --port 8000