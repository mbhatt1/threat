# Docker file for Lambda layer to ensure all dependencies are included
FROM public.ecr.aws/lambda/python:3.11

# Copy function code
COPY handler.py ${LAMBDA_TASK_ROOT}
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Copy ai_models directory
COPY ../../ai_models ${LAMBDA_TASK_ROOT}/ai_models

# Install the specified packages
RUN pip install -r requirements.txt -t .

# Set the CMD to your handler
CMD [ "handler.lambda_handler" ]