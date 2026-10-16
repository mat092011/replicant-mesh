# CPython 3.12.15, Debian Bookworm, linux/amd64 manifest (not a mutable tag).
FROM python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/cache/huggingface HF_HUB_CACHE=/cache/huggingface/hub \
    HF_HUB_DISABLE_TELEMETRY=1 DO_NOT_TRACK=1 \
    OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 TOKENIZERS_PARALLELISM=false \
    PYTHONPATH=/app/src:/app

COPY docker/pytorch/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && python -m pip check
COPY docker/pytorch/verify_environment.py /opt/steamboat/verify_environment.py
RUN python /opt/steamboat/verify_environment.py
WORKDIR /app

FROM dependencies AS runtime
# tc is used only inside explicitly selected lab network namespaces. Versions
# are captured with each experiment; Python/model dependencies stay hash-locked.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY src /app/src
COPY lab /app/lab
COPY tests /app/tests
CMD ["python", "-m", "lab.benchmark", "check", "--backend", "pytorch"]
