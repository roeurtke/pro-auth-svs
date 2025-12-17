FROM maven:3.9.4-eclipse-temurin-17

# Install additional tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create workspace directory
RUN mkdir -p /workspace
WORKDIR /workspace

# Set up Maven with correct ENV syntax
ENV MAVEN_HOME=/usr/share/maven
ENV MAVEN_CONFIG=/root/.m2

# Use sleep infinity to keep container running (alternative to /bin/bash)
CMD ["sleep", "infinity"]