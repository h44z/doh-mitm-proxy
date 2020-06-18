# Dockerfile References: https://docs.docker.com/engine/reference/builder/
# This dockerfile uses a multi-stage build system to reduce the image footprint.

######-
# Start from the latest golang base image as builder image (only used to compile the code)
######-
FROM golang:1.14 as builder

RUN mkdir /build

# Copy the source from the current directory to the Working Directory inside the container
ADD . /build/

# Set the Current Working Directory inside the container
WORKDIR /build

# Build the Go app
RUN go build -o dohpd cmd/dohpd/main.go
RUN go build -o dohc cmd/dohclient/main.go

######-
# Here starts the main image
######-
FROM debian:buster

# Add Maintainer Info
LABEL maintainer="Christoph Haas <christoph.haas@student.uibk.ac.at>"

# Create a user for execution (non-root)
RUN adduser --system --shell /usr/sbin/nologin --home /app appuser
USER appuser

COPY --from=builder /build/dohpd /app/
COPY --from=builder /build/dohc /app/
COPY --from=builder /build/config.yml /app/config.yml

# Set the Current Working Directory inside the container
WORKDIR /app

# Command to run the executable
CMD [ "/app/dohpd" ]
