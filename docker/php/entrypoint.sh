#!/bin/sh
set -eu

mkdir -p /var/lib/cybershield/logs/siem-outbox /var/lib/cybershield/sessions
chown www-data:www-data /var/lib/cybershield /var/lib/cybershield/logs \
    /var/lib/cybershield/logs/siem-outbox /var/lib/cybershield/sessions

exec docker-php-entrypoint "$@"
