# Воспроизведение проверок без GUI (ядро — чистый Python). GUI: pip install -r requirements.txt
FROM python:3.12-slim
WORKDIR /app
COPY protolab ./protolab
ENTRYPOINT ["python", "-m", "protolab"]
CMD ["verify", "/data/demo/project.json"]
