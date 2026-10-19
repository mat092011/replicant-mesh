# Standard-library-only C2a foundation checks, independent of model runtimes.
FROM python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src:/app
WORKDIR /app
COPY . /app
CMD ["python", "-B", "-S", "scripts/check_participant_connector.py"]
