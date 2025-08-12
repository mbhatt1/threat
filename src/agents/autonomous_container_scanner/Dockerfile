FROM public.ecr.aws/lambda/python:3.11

# Install system dependencies
RUN yum install -y git && yum clean all

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent.py .

# Copy shared modules
COPY ../../shared /var/task/shared
COPY ../../ai_models /var/task/ai_models

# Set environment variables
ENV PYTHONPATH=/var/task
ENV AI_ANALYSIS_MODE=deep

# Lambda handler
CMD ["agent.lambda_handler"]