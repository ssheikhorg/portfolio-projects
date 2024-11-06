#!/bin/bash

# Setup and start cron
setup_cron() {
  CRON_SCHEDULE=${CRON_SCHEDULE:-"0 0 * * *"}  # Default to midnight every day if not set
  chmod +x /app/scripts/cron_script.sh

  # Add cron job to execute the cron_script.sh
  echo "$CRON_SCHEDULE /app/scripts/cron_script.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/mycron

  # Set permissions and register the cron job
  chmod 0644 /etc/cron.d/mycron
  crontab /etc/cron.d/mycron
  touch /var/log/cron.log

  # Start cron in the background
  cron
}

# Start the FastAPI application
start_app() {
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
}

# Run both cron and FastAPI
setup_cron
start_app
