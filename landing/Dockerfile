FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY index.md /usr/share/nginx/html/index.md
COPY demo.mp4 /usr/share/nginx/html/demo.mp4
COPY robots.txt /usr/share/nginx/html/robots.txt
COPY sitemap.xml /usr/share/nginx/html/sitemap.xml
COPY .well-known /usr/share/nginx/html/.well-known
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
