# Use the offical uv image with Python 3.12
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set the working directory
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy dependency files and install dependencies
# This layer is cached unless pyproject.toml or uv.lock changes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

# Copy the rest of the application files
# Note: large files like GeoLite2 and domyntrix.db are excluded by .dockerignore and bind-mounted
COPY . .

# Ensure the startup script is executable
RUN chmod +x start.sh

# Expose the application port
EXPOSE 5000

# Set the default command
CMD ["bash", "start.sh"]
