# sshleak lab image: vanilla OpenSSH builds (SHA256-pinned) + tcpdump + a pty typing driver.
# Runs with --network none: sessions and capture stay on the container's own loopback.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential zlib1g-dev libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY versions.txt build-openssh.sh /build/
RUN /build/build-openssh.sh

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 zlib1g tcpdump python3 procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/empty /run/sshd /lab \
    && useradd -r -d /var/empty -s /usr/sbin/nologin sshd \
    && useradd -m -s /bin/bash lab && usermod -p "*" lab \
    && printf "PS1='LAB\$ '\nexport HISTFILE=/dev/null\n" > /home/lab/.bashrc \
    && printf ". ~/.bashrc\n" > /home/lab/.bash_profile \
    && head -c 8000000 /dev/urandom > /home/lab/blob && chown lab:lab /home/lab/blob
COPY --from=build /opt /opt
COPY driver.py /lab/driver.py
LABEL org.sshleak.lab="1"
