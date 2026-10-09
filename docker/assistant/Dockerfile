FROM python:3.13.15-slim-bookworm
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/cybershield-assistant
COPY ia/assistant-requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --system --gid 10002 cybershield \
    && useradd --system --uid 10002 --gid 10002 --no-create-home cybershield
COPY ia/assistant_core.py ia/assistant_graph.py ia/assistant_service.py ./
USER 10002:10002
EXPOSE 5100
ENTRYPOINT ["python", "assistant_service.py", "--host", "0.0.0.0", "--port", "5100"]
