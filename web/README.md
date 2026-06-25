# ABAC-NDN Documentation Website

A React-based documentation site for the ABAC-NDN library.

## Prerequisites

Choose one of the two options below. You only need one.

| Option | Requires |
|--------|----------|
| Docker (recommended) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| Local | [Node.js](https://nodejs.org/) v18 or newer |

---

## Option 1 — Docker Compose (recommended)

No Node.js installation needed. Docker handles everything.

```bash
# From the web/ directory:
docker compose up
```

The first run downloads the Node image and installs dependencies — this takes a minute. Subsequent starts are instant.

Open your browser at **http://localhost:5173**

To stop the server press `Ctrl + C`, then run:

```bash
docker compose down
```

> **Hot reload** is enabled: any file you edit inside `web/` is reflected in the browser immediately without restarting the container.

---

## Option 2 — Local Development (no Docker)

```bash
# 1. From the web/ directory, install dependencies (only needed once):
npm install

# 2. Start the development server:
npm run dev
```

Open your browser at **http://localhost:5173**

---

## Build for Production

To generate a static bundle (e.g. for deployment on a web server):

```bash
npm run build
```

The output is placed in `web/dist/`. Serve it with any static file server
(nginx, Apache, GitHub Pages, etc.).

To preview the production build locally before deploying:

```bash
npm run preview
```
