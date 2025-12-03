# FAIR Tools

Tools for the FAIR protocol. Create keys, create and manage DIDs, and build signed metadata for WordPress plugins.

## Installation

```bash
npm install fair-tools
```

## Basic usage

### Create a DID

Creates a new FAIR DID and publishes it.

```bash
npm run create-did -- --directory ./dids
```

This generates rotation and verification keypairs, creates a DID, publishes it to plc.directory, and writes the keys to `<directory>/<did>.json` with secure permissions (0600).

> [!WARNING]  
> Back up this file immediately!  
> This file contains the private keys needed to manage your DID.  
> If you lose this file, you will lose control of your DID permanently.

### Build metadata

Builds signed FAIR metadata for a WordPress plugin release.

```bash
# Local usage with key file
npm run build-metadata -- \
  --did did:plc:xxx \
  --signing-file ./dids/did:plc:xxx.json \
  --plugin-file ./my-plugin/my-plugin.php \
  --zip-file ./my-plugin.zip \
  --url https://example.com/releases/my-plugin-1.0.0.zip \
  --metadata-file ./metadata.json \
  --output-file ./metadata.json

# CI usage with environment variable (set FAIR_PRIVATE_KEY)
npm run build-metadata -- \
  --did did:plc:xxx \
  --plugin-file ./my-plugin/my-plugin.php \
  --zip-file ./my-plugin.zip \
  --url https://example.com/releases/my-plugin-1.0.0.zip \
  --metadata-file ./metadata.json \
  --output-file ./metadata.json
```

Use `--signing-key` to specify which verification key to use from the key file (defaults to first key). If `--signing-file` is not provided, the `FAIR_PRIVATE_KEY` environment variable is used.

### Update DID service URL

Updates an existing DID to add your FAIR service URL.

```bash
npm run update-did -- \
  --did did:plc:xxx \
  --signing-file ./dids/did:plc:xxx.json \
  --url https://example.com/did:plc:xxx/metadata.json
```

Use `--signing-key` to specify which rotation key to use from the key file (defaults to first key). If `--signing-file` is not provided, the `FAIR_ROTATION_KEY` environment variable is used.

## DID management

Over time you may need to manage the keys for your DID.

### Add verification key

Generates a new verification key, adds it to an existing DID, and saves it to the key file.

```bash
npm run add-verification-key -- \
  --did did:plc:xxx \
  --signing-file ./dids/did:plc:xxx.json
```

Use `--signing-key` to specify which rotation key to use from the key file (defaults to first key). If `--signing-file` is not provided, the `FAIR_ROTATION_KEY` environment variable is used.

Use `--output-file` to save the new key to a different file instead of the signing file.

### Add rotation key

Generates a new rotation key, adds it to an existing DID, and saves it to the key file.

```bash
npm run add-rotation-key -- \
  --did did:plc:xxx \
  --signing-file ./dids/did:plc:xxx.json
```

Use `--signing-key` to specify which rotation key to use from the key file (defaults to first key). If `--signing-file` is not provided, the `FAIR_ROTATION_KEY` environment variable is used.

Use `--output-file` to save the new key to a different file instead of the signing file.

### Revoke rotation key

Revokes a rotation key from an existing DID. You cannot revoke the key used to sign the operation, and at least one rotation key must remain.

```bash
npm run revoke-rotation-key -- \
  --did did:plc:xxx \
  --revoke did:key:zQ3sh... \
  --signing-file ./dids/did:plc:xxx.json
```

Use `--signing-key` to specify which rotation key to use for signing (defaults to first available that isn't being revoked). Use `--cleanup` to delete the revoked key from the key file after success.

## License

MIT
