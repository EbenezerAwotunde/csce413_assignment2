FROM python:3.11-slim

WORKDIR /app

# Install required packages
RUN pip install --no-cache-dir paramiko cryptography

# Copy honeypot files
COPY honeypot.py .
COPY logger.py .

# Create logs directory
RUN mkdir -p /app/logs

# Expose SSH port
EXPOSE 22

# Run the honeypot
CMD ["python", "-u", "honeypot.py"]
