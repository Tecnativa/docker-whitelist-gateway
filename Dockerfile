FROM python:3-alpine

ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["proxy"]
HEALTHCHECK CMD ["healthcheck"]

RUN apk add --no-cache -t .build build-base curl-dev && \
    apk add --no-cache iptables ipset iproute2 dnsmasq && \
    apk add --no-cache libcurl && \
    pip install --no-cache-dir dnspython dumb-init pycurl && \
    apk del .build

ENV NAMESERVERS="208.67.222.222 8.8.8.8 208.67.220.220 8.8.4.4" \
    PORT="*" \
    LISTEN_PORT=15000 \
    RESOLVE_INTERVAL=60 \
    PRE_RESOLVE=0 \
    MODE=tcp \
    VERBOSE=0 \
    MAX_CONNECTIONS=100 \
    UDP_ANSWERS=1 \
    HTTP_HEALTHCHECK=0 \
    HTTP_HEALTHCHECK_URL="http://\$TARGET/" \
    SMTP_HEALTHCHECK=0 \
    SMTP_HEALTHCHECK_URL="smtp://\$TARGET/" \
    SMTP_HEALTHCHECK_COMMAND="HELP" \
    DNS_UPSTREAMS="1.1.1.1 8.8.8.8" \
    RESOLVE_INTERVAL="60"

COPY proxy.py /usr/local/bin/proxy
COPY healthcheck.py /usr/local/bin/healthcheck
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
