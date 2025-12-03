# FAIR Tools

Tools for the FAIR protocol. Create keys, create and manage DIDs, and build signed metadata for WordPress plugins.

## Installation

```bash
npm install fair-tools
```

## CLI Commands

### create-did

Creates a new FAIR DID and publish it to plc.directory.

```bash
npm run create-did -- --directory ./dids
```

This generates rotation and verification keypairs, creates a DID, publishes it to plc.directory, and writes the keys to `<directory>/<did>.json` with secure permissions (0600).

> [!WARNING]  
> Back up this file immediately!  
> This file contains the private keys needed to manage your DID.  
> If you lose this file, you will lose control of your DID permanently.

### build-metadata

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

### update-did

Updates an existing DID to add your FAIR service endpoint.

```bash
npm run update-did -- \
  --did did:plc:xxx \
  --signing-file ./dids/did:plc:xxx.json \
  --url https://example.com/did:plc:xxx/metadata.json
```

## License

MIT
