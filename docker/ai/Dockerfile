FROM python:3.13.15-slim-bookworm AS model-build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY ia/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --target=/opt/python -r requirements.txt
COPY ia/features.py ./ia/features.py
COPY ia/train.py ./ia/train.py
COPY tests/fixtures/HttpParamsDataset/payload_train.csv ./tests/fixtures/HttpParamsDataset/payload_train.csv
RUN python ia/train.py --output-dir /opt/model/models

FROM python:3.13.15-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python
WORKDIR /opt/cybershield
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/cybershield/ia/models
COPY --from=model-build /opt/python /opt/python
COPY --from=model-build /opt/model/models/model.joblib ./ia/models/model.joblib
COPY ia/features.py ia/service.py ./ia/
USER 10001:10001
EXPOSE 5000
ENTRYPOINT ["python", "ia/service.py", "--host", "0.0.0.0"]
