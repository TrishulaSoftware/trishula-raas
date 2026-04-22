FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY raas_server.py .
EXPOSE 8443
CMD ["python", "raas_server.py"]
