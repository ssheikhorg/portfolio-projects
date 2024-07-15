#!/bin/bash

# Setup and start cron
setup_cron() {
  CRON_SCHEDULE=${CRON_SCHEDULE:-"0 0 * * *"}  # Default to every minute if not set
  chmod +x /app/scripts/cron_script.sh
  echo "$CRON_SCHEDULE /app/scripts/cron_script.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/mycron
  chmod 0644 /etc/cron.d/mycron
  crontab /etc/cron.d/mycron
  touch /var/log/cron.log
  cron
}

# Start the FastAPI application
start_app() {
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
}

setup_cron
start_app
