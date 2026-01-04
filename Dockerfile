# Use the official Playwright Python image which includes browsers and dependencies
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (redundant if base image has them, but ensures matching versions)
RUN playwright install chromium

# Copy the rest of the application
COPY . .

# Expose ports
# 8000: Web Dashboard
# 8081: Mitmproxy
EXPOSE 8000
EXPOSE 8081

# Run the startup script
CMD ["python", "start.py"]
