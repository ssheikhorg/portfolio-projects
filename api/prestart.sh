#!/bin/bash

# Add your cron job
echo "* * * * * /app/cron_script.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/mycron

# Give execution rights on the cron job
chmod 0644 /etc/cron.d/mycron

# Apply cron job
crontab /etc/cron.d/mycron

# Create the log file to be able to run tail
touch /var/log/cron.log

# Start cron
cron

# Your other prestart commands here
echo "Running prestart script..."
# ./your_other_startup_commands.sh

sleep 10 # temporay wait for db connection , TODO: Replace with wait script

# for later when we have different task managers
#celery -A src.worker.celery_app worker -c 5 --loglevel=info &