FROM python:3.12-alpine
WORKDIR /app
COPY server.py index.html ./
EXPOSE 8088
CMD ["python3", "/app/server.py"]
