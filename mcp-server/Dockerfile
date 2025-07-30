FROM node:18-alpine

# Install necessary tools
RUN apk add --no-cache \
    curl \
    git \
    docker-cli \
    && rm -rf /var/cache/apk/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy built application
COPY dist/ ./dist/

# Create necessary directories
RUN mkdir -p /app/scan-results /app/patching-workspace /app/reports

# Set permissions
RUN chown -R node:node /app

# Switch to non-root user
USER node

# Expose the HTTP port
EXPOSE 3000

# Health check using HTTP endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start the server in HTTP mode
ENV PORT=3000
CMD ["node", "dist/index.js"]
