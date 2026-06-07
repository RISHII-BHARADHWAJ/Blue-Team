FROM php:8.2-apache

# Install PHP extensions and system dependencies
RUN apt-get update && apt-get install -y \
    default-mysql-server \
    default-mysql-client \
    cron \
    supervisor \
    curl \
    && docker-php-ext-install mysqli pdo pdo_mysql \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers

# Set working directory
WORKDIR /var/www/html

# Copy source code
COPY . /var/www/html/

# Copy startup and cron scripts
COPY deploy/start.sh /start.sh
COPY deploy/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY deploy/crontab /etc/cron.d/threatpulse

# Permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod +x /start.sh \
    && chmod 0644 /etc/cron.d/threatpulse

# Update Apache config for .htaccess and rewrites
RUN echo '<Directory /var/www/html/> \n\
    Options Indexes FollowSymLinks \n\
    AllowOverride All \n\
    Require all granted \n\
</Directory>' > /etc/apache2/conf-available/ctf.conf \
    && a2enconf ctf

# Configure Apache to listen on PORT env var (Render uses dynamic ports)
RUN sed -i 's/Listen 80/Listen ${PORT}/g' /etc/apache2/ports.conf \
    && sed -i 's/:80/:${PORT}/g' /etc/apache2/sites-available/000-default.conf

# Environment defaults
ENV PORT=10000
ENV DB_HOST=localhost
ENV DB_USER=redteam_user
ENV DB_PASS=root
ENV DB_NAME=cybertech_db

EXPOSE 10000

CMD ["/start.sh"]
