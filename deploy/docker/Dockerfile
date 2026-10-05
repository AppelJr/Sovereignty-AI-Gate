FROM python:3.13-slim

LABEL org.opencontainers.image.title="Sovereignty AI Gate"
LABEL org.opencontainers.image.description="Sovereign on-device AI gate"

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e . || true

EXPOSE 8080
CMD ["python", "-m", "mcp_server"]
