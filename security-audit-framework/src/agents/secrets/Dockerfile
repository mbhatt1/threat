FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent code
COPY agent.py .

# Copy shared modules
COPY ../../shared /app/shared
COPY ../../ai_models /app/ai_models

# Set environment variables
ENV PYTHONPATH=/app:$PYTHONPATH
ENV AGENT_TYPE=secrets
ENV AI_POWERED=true
ENV BEDROCK_MODEL=claude-3-sonnet

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Run the AI-powered secrets detection agent
CMD ["python", "agent.py"]