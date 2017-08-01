FROM nginx:1.13.1-alpine

MAINTAINER Alessandro Resta <mail@alesr.me> @alesresta

# Remove default nginx
RUN rm -v /etc/nginx/nginx.conf

# Add custom nginx config
ADD ./resources/nginx/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

ENTRYPOINT ["nginx"]
