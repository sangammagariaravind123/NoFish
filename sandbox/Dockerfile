# Docker Caching Used : Placed the dependency installation before copying project files to leverage Docker's layer caching.
# This way, if there are no changes to the dependencies, Docker can reuse the cached layer, speeding up subsequent builds.

FROM python:3.10

WORKDIR /app

# Install dependencies first (better caching)
RUN pip install playwright fastapi uvicorn pydantic pandas scikit-learn joblib tqdm
RUN playwright install chromium --with-deps

# Copy project files after
COPY . .

CMD ["python3", "run_dataset.py"]


# docker build -t url-sandbox .
# docker run --rm -v ${PWD}:/app url-sandbox