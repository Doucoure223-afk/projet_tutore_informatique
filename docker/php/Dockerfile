FROM php:8.4.26-apache-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4-openssl-dev libonig-dev \
    && docker-php-ext-install -j"$(nproc)" mysqli curl mbstring opcache \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html
COPY app/ ./app/
COPY config/ ./config/
COPY database/ ./database/
COPY security/access.php security/bootstrap.php security/dashboard.php security/detector.php ./security/
COPY security/explanations.php security/hybrid_analyzer.php security/ia_analyzer.php ./security/
COPY security/ip-rules.php security/ip_access.php security/lab.php security/logger.php security/assistant.php security/assistant-client.php security/assistant-chat.php security/assistant-widget.js ./security/
COPY security/middleware.php security/response_handler.php security/console.css ./security/
COPY index.php ./.htaccess ./
COPY logs/.htaccess ./logs/.htaccess
COPY docker/php/apache-cybershield.conf /etc/apache2/conf-available/cybershield.conf
COPY docker/php/production.ini "$PHP_INI_DIR/conf.d/zz-cybershield.ini"
COPY docker/php/entrypoint.sh /usr/local/bin/cybershield-entrypoint
COPY docker/php/healthcheck.php /usr/local/bin/cybershield-healthcheck.php

RUN a2enconf cybershield \
    && chmod 0555 /usr/local/bin/cybershield-entrypoint \
    && chown -R root:root /var/www/html \
    && find /var/www/html -type d -exec chmod 0555 {} \; \
    && find /var/www/html -type f -exec chmod 0444 {} \;

ENTRYPOINT ["/usr/local/bin/cybershield-entrypoint"]
CMD ["apache2-foreground"]
