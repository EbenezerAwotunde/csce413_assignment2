FROM python:3.11-slim

WORKDIR /app

# Install required packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY knock_server.py knock_client.py protected_service.py start_services.sh ./

RUN chmod +x start_services.sh

EXPOSE 2222

CMD ["./start_services.sh"]
