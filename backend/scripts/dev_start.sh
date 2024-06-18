#!/bin/bash

# Setup and start cron
setup_cron() {
  chmod +x /app/scripts/cron_script.sh
  echo "0 0 * * * /app/cron_script.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/mycron
  chmod 0644 /etc/cron.d/mycron
  crontab /etc/cron.d/mycron
  touch /var/log/cron.log
  cron
}

# Start the FastAPI application
start_app() {
  uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
}

setup_cron
start_app
