#!/bin/bash

# Install and setup cron
setup_cron() {
  apt-get update && apt-get -y install cron
  chmod +x /usr/local/bin/freshclam_update.sh
  echo "0 0 * * * /usr/local/bin/freshclam_update.sh >> /var/log/cron.log 2>&1" > /etc/cron.d/clamav-update
  chmod 0644 /etc/cron.d/clamav-update
  crontab /etc/cron.d/clamav-update
  touch /var/log/cron.log
  cron
}

# Start the ClamAV daemon
start_clamav() {
  clamd
}

setup_cron
start_clamav
