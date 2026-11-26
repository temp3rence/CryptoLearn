# CryptoLearn / SafeBox

An educational Java application for **encrypting and decrypting text and files**, featuring a web interface, an HTTP API, and operation metadata stored in PostgreSQL.

The application uses Java's built-in `com.sun.net.httpserver.HttpServer`, without Spring or another web framework. It was built to explore HTTP request handling, JDBC, Java cryptography APIs, and containerization.

## Features

- Encrypt and decrypt text and files.
- **AES-256-GCM** encryption with keys derived from passwords using **PBKDF2-HMAC-SHA256**.
- A custom binary `.enc` file format containing the parameters needed for decryption.
- JSON-based HTTP API, with binary data transferred as Base64.
- Storage of successful operation metadata in PostgreSQL using JDBC transactions.
- Operation history and summary statistics displayed in the web interface.
- One-command startup of the application and PostgreSQL with Docker Compose.

> **Security notice:** This is an educational project, not a production-ready system for protecting sensitive data. Its cryptographic implementation has not undergone an independent security audit. Do not use real secrets or confidential files for testing.

## Tech Stack

- **Java**, Maven, Jackson
- **HTTP:** Java `HttpServer`
- **Cryptography:** Java Cryptography Architecture (JCA), AES-GCM, PBKDF2
- **Database:** PostgreSQL, JDBC
- **Frontend:** HTML, CSS, JavaScript
- **Containers:** Docker, Docker Compose

## Quick Start with Docker Compose

You need **Docker** with the Compose plugin (`docker compose`). Java and PostgreSQL do not need to be installed on the host machine.

1. Clone the repository and open its directory.
2. Create a local `.env` file from the example:

   ```bash
   cp .env.example .env
   ```

3. Set `DB_USER` and `DB_PASSWORD` in `.env`, replacing the example password:

   ```dotenv
   DB_USER=crypto
   DB_PASSWORD=replace_with_a_local_password
   ```

4. Build and start the containers:

   ```bash
   docker compose up -d --build
   ```

5. Open **http://localhost:8080** in your browser.

Check the HTTP health endpoint:

```bash
curl http://localhost:8080/api/health
# OK
```

Inspect container status and logs:

```bash
docker compose ps
docker compose logs -f app
```

Stop the application while preserving PostgreSQL data in its Docker volume:

```bash
docker compose down
```

> `docker compose down -v` **also removes the PostgreSQL data volume**. Do not use `-v` if you need to keep the data.

### Database Initialization

At startup, the application calls `Database.init()`, which creates the `operations`, `operation_metrics`, and `crypto_details` tables and their indexes if they do not already exist. PostgreSQL must be available before initialization runs.

## Configuration

The application reads `src/main/resources/application.properties`. Environment variables override file-based settings:

| Environment variable | Property | Purpose |
| --- | --- | --- |
| `DB_URL` | `db.url` | PostgreSQL JDBC URL |
| `DB_USER` | `db.user` | Database username |
| `DB_PASSWORD` | — | Database password; **required, environment-only** |

When running Java directly on the host, the JDBC URL can be `jdbc:postgresql://localhost:5432/cryptolearn`. With Docker Compose, the application connects using the database service name: `jdbc:postgresql://db:5432/cryptolearn`.

## HTTP API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Web interface |
| `GET` | `/api/health` | Basic HTTP health check (`OK`) |
| `POST` | `/api/safebox/encrypt` | Encrypt data |
| `POST` | `/api/safebox/decrypt` | Decrypt data |
| `GET` | `/api/operations` | Operation history (supports `limit`) |
| `GET` | `/api/admin/summary` | Aggregated operation statistics |

Example encryption request:

```bash
curl -X POST http://localhost:8080/api/safebox/encrypt \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "demo-password",
    "filename": "hello.txt",
    "plaintextBase64": "SGVsbG8h"
  }'
```

`plaintextBase64` contains the input bytes encoded as Base64 (`SGVsbG8h` represents `Hello!`). The response includes the encrypted `.enc` file encoded as Base64 and the encryption duration.

## Architecture

```text
Browser (HTML / CSS / JS)
          |
          | HTTP / JSON
          v
Java HttpServer
  |-- StaticFileHandler        -> static assets
  |-- EncryptHandler           -> encryption
  |-- DecryptHandler           -> decryption
  |-- OperationsHandler        -> history
  `-- AdminSummaryHandler      -> statistics
          |
          +-- SafeBoxCryptoService / EncryptedFileCodec
          `-- OperationsDao -> JDBC -> PostgreSQL
```

Operation persistence is transactional: metadata is stored across the `operations`, `operation_metrics`, and `crypto_details` tables. If any insert fails, the transaction is rolled back.

## Limitations

- Intended for learning and local use, not production deployment.
- Operation history and the admin summary are demonstration features, **not** a secure audit log or authenticated administration interface.
- The web interface loads an entire selected file into memory before sending it; large-file handling is not optimized.
- `/api/health` checks that the HTTP handler responds, not that the database connection is healthy.

## Project Status

Educational project. The following have been tested locally: Docker Compose startup, text encryption and decryption, PostgreSQL operation logging, operation history, and summary statistics.
