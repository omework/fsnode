# Use an official Ubuntu as a parent image
FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && \
    apt-get install -y build-essential \
                       libmagic-dev \
                       libjansson-dev \
                       libuv1-dev \
                       libduckdb-dev \
                       libssl-dev \
                       libzlog-dev \
                       wget \
                       git \
                       clang

# Set the working directory in the container
WORKDIR /workspace

# Copy the current directory contents into the container at /workspace
COPY . /workspace

# Compile the application
RUN make ubuntu

# Define the command to run the executable
CMD ["./fsnode"]