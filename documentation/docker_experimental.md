# Experimental Docker Compose Setup

> **Note:** The Docker Compose configuration is currently a **Work in Progress (WIP)** and has not been fully finalized. It is intended for local experimentation and community feedback.

The community edition repository contains an experimental setup to orchestrate the entire Trust Gateway ecosystem (NATS, Trust Gateway, Agent Host, SSI Agent, unified Executors, Portal) using Docker and Docker Compose.

You can find the Dockerfiles and compose layout in the [docker_experimental/](lianxi-community/docker_experimental/) directory.

## Current Status

- **Work in Progress:** Some configuration values and network routes are being actively refined.
- **Goal:** To provide a single-command setup for development, testing, and exploration of the open-source community edition.
- **Feedback Welcome:** If you run into issues or have ideas for improving container health checks or orchestration pathways, please open an issue or pull request.

## Setup Tutorial

A step-by-step tutorial is available at [docker_experimental/how_to.md](lianxi-community/docker_experimental/how_to.md). It covers:
1. Generating the required Ed25519 grant signing key pair.
2. Setting up NATS client nkeys and authorization dynamically.
3. Building and running all components using `start.sh`.
4. URLs for verification (UI, Gateway API, Agent Host, NATS monitoring).
