FROM python:3.12-slim
WORKDIR /artifact
RUN apt-get update && apt-get install -y --no-install-recommends gcc binutils unzip && rm -rf /var/lib/apt/lists/*
COPY . /artifact
RUN python3 -m pip install --no-cache-dir -r requirements.txt
CMD ["python3", "scripts/run_usenix_required.py"]
