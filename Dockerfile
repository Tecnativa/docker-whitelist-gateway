FROM python:3-alpine

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        curl-dev \
    && apk add --no-cache \
        dumb-init \
        dnsmasq \
        iproute2 \
        ipset \
        iptables \
        libcurl \
    && pip install --no-cache-dir \
        dnspython \
        pycurl \
    && apk del .build-deps

ENV NAMESERVERS="1.1.1.1 8.8.8.8" \
    PORT="*" \
    LISTEN_PORT="15000" \
    RESOLVE_INTERVAL="60" \
    PRE_RESOLVE="0" \
    MODE="tcp" \
    VERBOSE="0" \
    MAX_CONNECTIONS="100" \
    UDP_ANSWERS="1" \
    HTTP_HEALTHCHECK="0" \
    HTTP_HEALTHCHECK_URL="http://\$TARGET/" \
    SMTP_HEALTHCHECK="0" \
    SMTP_HEALTHCHECK_URL="smtp://\$TARGET/" \
    SMTP_HEALTHCHECK_COMMAND="HELP" \
    DNS_UPSTREAMS="1.1.1.1 8.8.8.8"

COPY proxy.py /usr/local/bin/proxy
COPY healthcheck.py /usr/local/bin/healthcheck
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x \
    /usr/local/bin/proxy \
    /usr/local/bin/healthcheck \
    /usr/local/bin/entrypoint.sh

ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["proxy"]
HEALTHCHECK CMD ["healthcheck"]
