# 🐳 PHANTOM MCP - Dockerfile
# Base image: Python 3.11 Slim (Lightweight & Secure)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHANTOM_SAFE_MODE=false

# Install system dependencies (Nmap is required for scanning)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create directory for logs and reports
RUN mkdir -p logs reports

# Expose port (if we add stdio-over-tcp in future, but currently stdio is standard)
# MCP usually runs over Stdio, so Docker will be run interactively
# ENTRYPOINT ["python", "-m", "phantom.server"]

# For MCP Stdio compatibility, we default to running the module
CMD ["python", "-m", "phantom.server"]
