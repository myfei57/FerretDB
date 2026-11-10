---
sidebar_position: 2
description: Learn to secure connections using TLS
---

# TLS connections

It is possible to encrypt connections between FerretDB and clients by using TLS.
All you need to do is to start the server with the following flags or environment variables:

- `--listen-tls` / `FERRETDB_LISTEN_TLS` specifies the TCP hostname and port
  that will be used for listening for incoming TLS connections.
  If empty, TLS listener is disabled;
- `--listen-tls-cert-file` / `FERRETDB_LISTEN_TLS_CERT_FILE` specifies the PEM encoded, TLS certificate file
  that will be presented to clients;
- `--listen-tls-key-file` / `FERRETDB_LISTEN_TLS_KEY_FILE` specifies the TLS private key file
  that will be used to decrypt communications;
- `--listen-tls-ca-file` / `FERRETDB_LISTEN_TLS_CA_FILE` specifies the root CA certificate file
  that will be used to verify client certificates.

Then use `tls` query parameters in MongoDB URI for the client.
You may also need to set `tlsCAFile` parameter if the system-wide certificate authority did not issue the server's certificate.
See documentation for your client or driver for more details.
Example: `mongodb://ferretdb:27018/?tls=true&tlsCAFile=companyRootCA.pem`.

## Setting up TLS connections

In the following examples, FerretDB uses TLS certificates to secure the connection.
The `ferretdb` server uses TLS server certificate file, TLS private key file and root CA certificate file.

```text
server-certs/
├── rootCA-cert.pem
├── server-cert.pem
└── server-key.pem
```

The client uses TLS client certificate file and root CA certificate file.

```text
client-certs/
├── client.pem
└── rootCA-cert.pem
```

### Setting up TLS via Docker

When using Docker to run `ferretdb` server, the `docker-compose.yml` below shows how to set up TLS connections.
The Docker host requires certificates `server-certs` directory,
and volume is mounted from `./server-certs` of Docker host to `/etc/certs` of Docker container.

```yaml
services:
  postgres:
    image: ghcr.io/ferretdb/postgres-documentdb:17
    environment:
      - POSTGRES_USER=username
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=postgres
    volumes:
      - ./data:/var/lib/postgresql/data

  ferretdb:
    image: ghcr.io/ferretdb/ferretdb:2
    restart: on-failure
    ports:
      - 27018:27018
    environment:
      - FERRETDB_POSTGRESQL_URL=postgres://username:password@localhost:5432/postgres
      - FERRETDB_LISTEN_TLS=:27018
      - FERRETDB_LISTEN_TLS_CERT_FILE=/etc/certs/server-cert.pem
      - FERRETDB_LISTEN_TLS_KEY_FILE=/etc/certs/server-key.pem
      - FERRETDB_LISTEN_TLS_CA_FILE=/etc/certs/rootCA-cert.pem
    volumes:
      - ./server-certs:/etc/certs

networks:
  default:
    name: ferretdb
```

To start `ferretdb`, run the following command:

```sh
docker compose up
```

In the following example, a client connects to MongoDB URI using TLS certificates as `username`.
It uses Docker volume to mount `./clients-certs` of Docker host to `/clients` Docker container.

Connect to `ferretdb` server using `mongosh` client:

```sh
docker run --rm -it \
  --network=ferretdb \
  --volume ./client-certs:/clients \
  --entrypoint=mongosh \
  mongo 'mongodb://username:password@host.docker.internal:27018/?tls=true&tlsCertificateKeyFile=/clients/client.pem&tlsCaFile=/clients/rootCA-cert.pem'
```

## Rotating TLS certificates and CA bundles

A running TLS listener can switch its server certificate, private key and, when mTLS is
enabled, its client CA bundle without closing or re-binding the listening TCP port.
The Go API entry point is the `ReloadTLSBundle` method of the listener
(`internal/clientconn` package), which can be used by embedders and administrative
integrations after replacing the PEM files on disk.

A reload is fully atomic:

- every candidate file is read twice and completely validated before anything is
  published, so a file that changes while it is read, a corrupt PEM block, or a
  certificate/key pair that does not match makes the reload fail and leaves the
  currently running configuration untouched;
- each successful reload publishes one immutable TLS configuration generation, and every
  new handshake pins a complete generation through the standard
  `tls.Config.GetConfigForClient` mechanism, so a handshake can never use a new server
  certificate together with an old client CA pool;
- concurrent reloads are serialized and committed with strictly increasing, contiguous
  generation numbers, and reloads after the listener is closed are rejected;
- the caller may pass an opaque bundle identifier and/or the expected SHA-256 digest of
  the complete bundle to make sure the files that were read belong to the intended
  deployment and were not mixed across deployments.

The client authentication mode is fixed when the listener starts.

- When the `--listen-tls-ca-file` flag is set, the listener requires and verifies client
  certificates; a reload can replace the trusted client CAs but can never downgrade that
  requirement, and an empty or unreadable CA file is rejected instead of weakening it.
- When the flag is not set, client certificate verification stays disabled; an empty or
  stray CA file can never enable mTLS by itself.

Reloading a bundle only affects new handshakes on the inbound TLS listener.

- Connections that were already established keep using the bundle they handshaked with
  until they disconnect, exactly as TLS guarantees.
  Rotating the client CA therefore does not retroactively revoke or close existing
  connections; clients that must be disconnected need to be closed separately.
- The proxy connection and the backend database connection keep their own TLS
  configuration and are never affected by an inbound bundle reload.

Private key contents are never written to logs or metrics.
Reloads are counted by the `ferretdb_client_tls_bundle_reloads_total` metric (with `result`
and fixed `reason` labels), and `ferretdb_client_tls_bundle_generation` exposes the
generation currently used by new handshakes; log messages only contain the generation
number, the caller-provided identifier and the bundle digest.
