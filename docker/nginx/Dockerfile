FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Add our config
COPY docker/nginx/nginx.conf /etc/nginx/conf.d/

# Copy built React frontend
COPY frontend/dist/ /usr/share/nginx/html/

EXPOSE 80
