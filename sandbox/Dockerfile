FROM python:3.10

WORKDIR /app
COPY . .

RUN pip install playwright fastapi uvicorn
RUN playwright install chromium --with-deps

CMD ["python", "sandbox.py"]

# docker run --rm -v ${PWD}:/app url-sandbox