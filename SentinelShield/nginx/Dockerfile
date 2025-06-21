# Start from the official Nginx image
FROM nginx:latest

# Remove the default configuration file that might interfere
RUN rm -f /etc/nginx/conf.d/default.conf

# Create empty log files with the correct permissions.
# This is the crucial step to prevent Nginx from creating symlinks to /dev/stdout.
RUN touch /var/log/nginx/access.log /var/log/nginx/error.log && \
    chown -R nginx:nginx /var/log/nginx

# Copy our custom, complete nginx.conf to the main configuration location
COPY nginx.conf /etc/nginx/nginx.conf 