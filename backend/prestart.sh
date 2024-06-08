#!/bin/bash

chmod +x /app/cron_script.sh

# Add your cron job
echo "0 0 * * * /app/cron_script.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/mycron

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