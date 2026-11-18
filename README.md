# goclient

Go client library for [Sharqey](https://sharqey.com), an end-to-end encrypted password and
secrets manager. It is the shared core of the Sharqey CLI, the desktop app and the
[Terraform provider](https://github.com/sharqey/terraform-provider-sharqey).

All encryption happens on the client. The server only ever stores ciphertext, so this
library holds everything that touches key material.

| Package | What it does |
|---|---|
| `apiclient` | HTTP client for the Sharqey API (login, organizations, groups, secrets, devices). |
| `pgpcrypto` | OpenPGP identity keys (Curve25519/EdDSA), fingerprints, the group-key model, AES-256-GCM. |
| `filesecret` | File secrets: blob format (`IV \|\| AES-GCM(file_key, file)`), metadata, upload and download through presigned URLs. |
| `localvault` | The `.sharqey` local database file format: create, unlock (password, system GPG), read and write secrets. Works fully offline. |

The version history of the `.sharqey` format is documented next to `localvault.FormatVersion`.
`localvault/testdata/v5-file.sharqey` with `v5-file.expected.json` is a golden file for
implementations in other languages: open it with the password from the `.expected.json` and you
should read the same values. `pgpcrypto/testdata/group-key-vector.json` is a fixed test vector for
the group-key algorithm.

The keys and passwords in `testdata/` are synthetic and exist only for tests.

## Install

```sh
go get github.com/sharqey/goclient
```

## Stability

The API is used by the Sharqey clients and may change before 1.0. Pin a version.

## License

Apache License 2.0, see [LICENSE](LICENSE).
