FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir fastapi uvicorn pydantic httpx pillow playwright easyocr

EXPOSE 10000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
