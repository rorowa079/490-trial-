# Edge-device image. Not yet built or run on a Pi: treat as a starting point.
FROM node:22-slim AS ui
WORKDIR /ui
COPY dashboard/package*.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends tpm2-tools libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/vrs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY config/ config/
COPY db/ db/
COPY src/ src/
COPY scripts/ scripts/
COPY --from=ui /ui/dist dashboard/dist
ENV PYTHONPATH=/opt/vrs/src
# Mount /opt/vrs/data as a volume and pass the TPM through: --device /dev/tpmrm0
CMD ["python", "-m", "vrs.app"]
