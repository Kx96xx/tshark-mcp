# tshark-mcp in a container: tshark from Debian, the server installed from this checkout,
# a non-root user and no writable path but /tmp. Build and run:
#
#   docker build -t tshark-mcp .
#   docker run --rm -i --read-only --tmpfs /tmp --cap-drop ALL --network none \
#     --security-opt no-new-privileges --memory 2g -v /path/to/pcaps:/captures:ro tshark-mcp
#
# The server speaks MCP over stdio, so a client starts that `docker run` command as its
# server command. Captures are read from /captures (mounted read-only); extra arguments
# after the image name replace the default `--allow-dir /captures`.

ARG PYTHON_IMAGE=python:3.12-slim-trixie
FROM ${PYTHON_IMAGE}

# The tshark release series this image is built and tested with; the build fails if the
# distribution no longer ships it, so a tshark upgrade is always a visible change here.
ARG TSHARK_SERIES=4.4

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends "tshark=${TSHARK_SERIES}.*" \
 && rm -rf /var/lib/apt/lists/* \
 && tshark --version | head -1 | grep -q "TShark (Wireshark) ${TSHARK_SERIES}\." \
 && groupadd --system --gid 10001 tshark-mcp \
 && useradd --system --uid 10001 --gid tshark-mcp --home-dir /home/tshark-mcp --create-home \
      --shell /usr/sbin/nologin tshark-mcp \
 && mkdir /captures

COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN pip install /src && rm -rf /src

USER tshark-mcp:tshark-mcp
WORKDIR /home/tshark-mcp
ENV TSHARK_MCP_TSHARK=/usr/bin/tshark

LABEL org.opencontainers.image.title="tshark-mcp" \
      org.opencontainers.image.description="Read-only MCP server for packet captures with tshark" \
      org.opencontainers.image.source="https://github.com/Kx96xx/tshark-mcp" \
      org.opencontainers.image.licenses="MIT" \
      io.github.kx96xx.tshark-series="${TSHARK_SERIES}"

# A stdio server has no port to probe: healthy means the package imports and tshark runs.
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import subprocess, tshark_mcp; subprocess.run(['/usr/bin/tshark', '--version'], check=True, capture_output=True, timeout=8)"]

ENTRYPOINT ["tshark-mcp"]
CMD ["--allow-dir", "/captures"]
