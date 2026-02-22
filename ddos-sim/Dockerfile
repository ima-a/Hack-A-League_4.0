FROM alpine:latest

RUN apk add --no-cache apache2-utils

COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/bin/sh", "/attack.sh"]
