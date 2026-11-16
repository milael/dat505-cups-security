

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      cups-ipp-utils \
      avahi-daemon \
      dbus \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8631

COPY docker/printer/start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/bin/sh", "/start.sh"]
