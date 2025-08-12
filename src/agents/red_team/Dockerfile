FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .
COPY ../../shared /app/shared

# Set environment variables
ENV PYTHONPATH=/app:$PYTHONPATH
ENV AWS_DEFAULT_REGION=us-east-1

# Run the agent
CMD ["python", "agent.py"]