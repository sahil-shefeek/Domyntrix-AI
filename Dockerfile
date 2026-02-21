# Use a slim Python 3.12 image as the base
FROM python:3.12-slim

# Install uv globally
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set the working directory
WORKDIR /app

# Copy dependency files and install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

# Copy the rest of the application files
COPY . .

# Ensure the startup script is executable
RUN chmod +x start.sh

# Pre-create the data directory for the SQLite volume mount
RUN mkdir -p /app/data

# Expose the application port
EXPOSE 5000

# Set the default command
CMD ["./start.sh"]
