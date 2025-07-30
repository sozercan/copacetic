FROM node:18-alpine

# Install necessary tools
RUN apk add --no-cache \
    curl \
    git \
    docker-cli \
    go \
    build-base \
    && rm -rf /var/cache/apk/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Copa (Copacetic) - Copy locally built binary
COPY copa /usr/local/bin/copa
RUN chmod +x /usr/local/bin/copa

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy built application
COPY dist/ ./dist/

# Create necessary directories and set permissions
RUN mkdir -p /app/scan-results /app/patching-workspace /app/reports

# Create entrypoint script for Docker socket access
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo '# Ensure Docker socket access' >> /app/entrypoint.sh && \
    echo 'if [ -S /var/run/docker.sock ]; then' >> /app/entrypoint.sh && \
    echo '  chmod 666 /var/run/docker.sock' >> /app/entrypoint.sh && \
    echo 'fi' >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Remove the USER directive to run as root
# USER node

# Expose the HTTP port
EXPOSE 3000

# Health check using HTTP endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start the server in HTTP mode with proper entrypoint
ENV PORT=3000
ENV DEBUG=1
ENV NODE_ENV=development
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["node", "dist/index.js"]
