FROM python:3.10.16-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/cache/huggingface HF_HUB_CACHE=/cache/huggingface/hub \
    PETALS_CACHE=/cache/huggingface/hub \
    OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 TOKENIZERS_PARALLELISM=false \
    HF_HUB_DISABLE_TELEMETRY=1 DO_NOT_TRACK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential ca-certificates iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pip==24.3.1 setuptools==75.6.0 wheel==0.45.1 \
    && pip install --no-cache-dir torch==2.3.1+cpu \
       --index-url https://download.pytorch.org/whl/cpu
COPY docker/requirements.txt docker/build-constraints.txt /tmp/
# PIP_CONSTRAINT is inherited by isolated PEP 517 build subprocesses. Pinning
# setuptools only in the outer environment would not protect old Hivemind builds.
RUN PIP_CONSTRAINT=/tmp/build-constraints.txt pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip check

WORKDIR /app
COPY lab /app/lab
COPY tests /app/tests
RUN python -m compileall -q lab tests && python -m unittest discover -s tests
CMD ["python", "-m", "lab.launch", "client"]
