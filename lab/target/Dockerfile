FROM nginx:1.27-alpine
RUN apk add --no-cache openssh-server && ssh-keygen -A \
 && adduser -D -s /bin/sh labuser && echo "labuser:$(head -c 18 /dev/urandom | base64)" | chpasswd \
 && for i in 0 1 2 3 4; do echo "<h1>lab page $i</h1>" > /usr/share/nginx/html/page$i.html; done
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
