FROM maven:3.9.11-eclipse-temurin-21 AS opsin
WORKDIR /build
COPY pom.xml ./
COPY opsin-core ./opsin-core
COPY opsin-inchi ./opsin-inchi
COPY opsin-cli ./opsin-cli
RUN mvn -B -ntp -DskipTests package

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless fonts-dejavu-core libxrender1 libxext6 curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    OPSIN_JAR=/app/opsin.jar
COPY mcp/pyproject.toml mcp/uv.lock ./
RUN uv sync --locked --no-dev
COPY --from=opsin /build/opsin-cli/target/opsin-cli-3.0-SNAPSHOT-jar-with-dependencies.jar /app/opsin.jar
COPY mcp/opsin_mcp.py ./
USER 10001:10001
EXPOSE 8080
CMD ["/app/.venv/bin/python", "opsin_mcp.py"]
