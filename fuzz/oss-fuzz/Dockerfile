# OSS-Fuzz Dockerfile for Unicity
FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libboost-system-dev \
    && rm -rf /var/lib/apt/lists/*

# For local testing: copy project instead of cloning
# Comment out when submitting to OSS-Fuzz
COPY . $SRC/unicity

# Set working directory
WORKDIR $SRC/unicity

# Copy build script
COPY build.sh $SRC/
