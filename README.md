# FAIR Tools

Tools for the FAIR protocol. Create keys, create and manage DIDs, and build signed metadata for WordPress plugins.

> [!CAUTION]  
> This package is not production ready and is under heavy development. Do not use this unless you are comfortable testing the FAIR protocol and ecosystem and for things to change and break.

> [!IMPORTANT]  
> This is not an official FAIR tool.  
> The license of this repo does facilitate it being transferred to The FAIR Web Foundation at a later date should they wish.

## Installation

```bash
npm install fair-tools
```

## Basic usage

The basic steps to set up a plugin for distribution via FAIR is:

- Create a DID.
- Save the generated signing keys somewhere safe.
- Add the DID to your plugin header and publish it.
- Build FAIR metadata for the package and publish it.
- Point your DID to the metadata document.

The DID and key setup is only required once. Subsequent updates to your plugin just require you to build the FAIR metadata for the package and publish it.

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

### Revoke verification key

Revokes a verification key from an existing DID.

```bash
npm run revoke-verification-key -- \
  --did did:plc:xxx \
  --revoke did:key:z6Mk... \
  --signing-file ./dids/did:plc:xxx.json
```

Use `--signing-key` to specify which rotation key to use for signing. Use `--cleanup` to delete the revoked key from the key file after success.

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
