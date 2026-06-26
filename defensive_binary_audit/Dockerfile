# Isolated CI environment for defensive binary validation pipeline
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    WINEPREFIX=/tmp/defensive-audit-wine-prefix \
    WINEDEBUG=-all \
    DISPLAY=:99 \
    SKIP_APT=1

RUN dpkg --add-architecture i386 && \
    apt-get update -qq && \
    apt-get install -y -qq \
      python3 python3-pip python3-venv python3-dev \
      wine64 wine32 winbind \
      xvfb x11-utils \
      build-essential libyara-dev \
      ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -q --upgrade pip && \
    pip install --no-cache-dir -q -e .

RUN mkdir -p /tmp/defensive-audit-wine-prefix logs patch_artifacts && \
    chmod +x /app/scripts/setup_ci.sh /app/scripts/docker-entrypoint.sh

VOLUME ["/app/patch_artifacts", "/tmp/defensive-audit-wine-prefix"]

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["bash"]

# One-command full test:
#   docker build -t defensive-binary-audit .
#   docker run --rm -v $(pwd)/samples:/samples defensive-binary-audit \
#     --full-test /samples/target.exe
