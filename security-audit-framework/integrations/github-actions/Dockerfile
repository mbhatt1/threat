FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN pip install --no-cache-dir awscli

# Copy action files
WORKDIR /action
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.py /action/
COPY ai_security_scanner.py /action/

# Make entrypoint executable
RUN chmod +x /action/entrypoint.py

ENTRYPOINT ["python", "/action/entrypoint.py"]