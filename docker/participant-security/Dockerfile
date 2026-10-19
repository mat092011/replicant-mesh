# Isolated C1a validation; the historical CPU and Petals images stay independent.
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

COPY docker/participant-security/requirements.lock /tmp/participant-security.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/participant-security.lock \
    && python -m pip check \
    && python /opt/steamboat/verify_environment.py \
    && python -c "import cryptography,cffi,pycparser; assert (cryptography.__version__,cffi.__version__,pycparser.__version__)==('50.0.2','2.1.1','3.11')"

FROM dependencies AS validation
RUN mkdir -p /opt/steamboat-test/identity-root \
    && chmod 0700 /opt/steamboat-test/identity-root
COPY --chown=65534:65534 --chmod=0600 docker/participant-security/foreign-owner-fixture.txt /opt/steamboat-test/identity-root/foreign.pem
COPY . /app
CMD ["python", "-B", "scripts/check_participant_security.py"]
