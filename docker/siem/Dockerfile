FROM python:3.13.15-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/cybershield
COPY scripts/siem_forwarder.py ./siem_forwarder.py
RUN mkdir -p /var/lib/cybershield/logs/siem-outbox \
    && chown 33:33 /var/lib/cybershield/logs/siem-outbox \
    && chmod 0700 /var/lib/cybershield/logs/siem-outbox
USER 33:33
ENTRYPOINT ["python", "siem_forwarder.py"]
