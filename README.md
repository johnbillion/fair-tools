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
npm run build-metadata -- \
  --keyfile ./dids/did:plc:xxx.json \
  --plugin ./my-plugin/my-plugin.php \
  --zip ./my-plugin.zip \
  --url https://example.com/releases/my-plugin-1.0.0.zip \
  --output ./metadata.json
```

### update-did

Updates an existing DID to add your FAIR service endpoint.

```bash
npm run update-did -- \
  --keyfile ./dids/did:plc:xxx.json \
  --url https://example.com/did:plc:xxx/metadata.json
```

## License

MIT
