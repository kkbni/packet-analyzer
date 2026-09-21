FROM python:3.12-slim

# install the necessary utilities for the 'ifconfig' command
RUN apt-get update && \
    apt-get install -y net-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src ./src

ENTRYPOINT ["python3", "-m", "src.analyzer"]
CMD ["-i", "eth0"]