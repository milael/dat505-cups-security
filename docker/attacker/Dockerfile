
FROM python:3.12-slim

# Install packet-capture and networking utilities.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        iproute2 \
        iputils-ping \
        curl \
	iptables \
    && rm -rf /var/lib/apt/lists/*

# Install Scapy for packet construction and analysis.
RUN pip install --no-cache-dir "scapy>=2.6,<3"

WORKDIR /workspace

# Keep the container running for interactive experiments.
CMD ["sleep", "infinity"]


