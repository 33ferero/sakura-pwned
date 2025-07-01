# The vulnerable Sakura C2 server.
# glibc 2.39 (>= the GLIBC_2.38 the bundled binary requires).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        netcat-traditional \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set nc /bin/nc.traditional

WORKDIR /opt/sakura
# Sakura_Login.txt is required: BotWorker fopen()s it with no NULL check, so the
# C2 segfaults on every login if it is missing.
COPY Sakura botnet/Sakura_Login.txt /opt/sakura/

# RCE goal: root-only, so only the reverse-shell exploit (root) can read it.
RUN echo 'flag{sakura_pwned}' > /root/flag.txt \
    && chmod 600 /root/flag.txt

EXPOSE 12345 54321

CMD ["./Sakura", "12345", "1", "54321"]
