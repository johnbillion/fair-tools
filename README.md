# FAIR Tools

A library of Node.js tools for [FAIR](https://fair.pm/) that can be used by authors of plugins and themes for WordPress. Create keys, create DIDs, manage DID documents, and build signed FAIR metadata.

This library focuses on providing FAIR tools for the WordPress ecosystem, but its tools are also applicable to FAIR and DID PLC in general.

> [!CAUTION]  
> This package is not production ready and is under heavy development. Do not use this unless you are comfortable testing the FAIR protocol and handling breaking changes, including breaking changes to storage of private keys.  

> [!IMPORTANT]  
> This is not an official FAIR tool.  
> Its license facilitates it being transferred to The FAIR Web Foundation at a later date should they wish.  

## Installation

```bash
npm install --save-dev fair-tools
```

Then add `fair-tools` to your `package.json` scripts:

```json
{
  "scripts": {
    "fair-tools": "fair-tools"
  }
}
```

Run with:

```bash
npm run fair-tools -- metadata build --plugin-file ./my-plugin.php ...
```

## CLI reference

Run `npm run fair-tools` to see all available commands:

```
Usage: fair-tools <command> [options]

Commands:
  did create                   Create a new DID
  did service add              Add a service URL to a DID
  did service replace          Replace a service URL in a DID
  did service remove           Remove a service URL from a DID
  did verification-key add     Add a verification key
  did verification-key revoke  Revoke a verification key
  did rotation-key add         Add a rotation key
  did rotation-key revoke      Revoke a rotation key
  did aka add                  Add a URL to the alsoKnownAs field
  did aka replace              Replace a URL in the alsoKnownAs field
  did aka remove               Remove a URL from the alsoKnownAs field
  did domain verify            Verify a domain's DNS record for a DID
  did domain verify-alias      Verify alsoKnownAs domain aliases for a DID
  metadata build               Build a FAIR metadata document

Run 'fair-tools <command> --help' for more information on a command.
```

## Basic usage

The basic steps to set up a plugin for distribution via FAIR are:

1. Generate a DID and save its signing keys somewhere safe.
2. Add the DID to your plugin header and publish it.
3. Build the FAIR metadata for the package and publish it.
4. Point your DID to the URL of the metadata document.

The initial setup of the DID only happens once. Subsequent updates to your plugin just require you to build the FAIR metadata for the package and publish it.

### Create a DID

Creates a new DID and publishes it.

```bash
npm run fair-tools -- did create --directory ./dids
```

This generates rotation and verification keypairs, creates a DID, publishes it to plc.directory, and writes the keys to `<directory>/<did>.json` with secure permissions (0600).

> [!WARNING]
> Back up this file immediately!
> This file contains the private keys needed to manage your DID.
> If you lose this file, you will lose control of your DID permanently.

### Add the DID to your plugin header

Manually add the new DID to the header of your plugin. The `did:plc:` prefix must be included.

```diff
  * Plugin Name: My Plugin
+ * Plugin ID: did:plc:abcdefghijklmnopqrstuvwx
  * Version: 1.0.0
```

### Signing keys

Most subsequent commands after creating a DID require a signing key. There are two ways to provide one:

1. **Key file**: Use `--signing-file` to specify a key file. The file can be either:
   - A JSON file containing your keys (use `--signing-key` to select a specific key; defaults to first key)
   - A plain text file containing a multibase base58btc encoded private key (starts with 'z')

2. **Environment variable**: If `--signing-file` is not provided, the command falls back to an environment variable:
   - `FAIR_PRIVATE_KEY` for metadata signing (verification key)
   - `FAIR_ROTATION_KEY` for DID operations (rotation key)

### Build metadata

Builds signed FAIR metadata for a WordPress plugin release.

```bash
npm run fair-tools -- metadata build \
  --did did:plc:xxx \
  --plugin-file ./my-plugin/my-plugin.php \
  --zip-file ./my-plugin.zip \
  --url https://example.com/releases/my-plugin-1.0.0.zip \
  --metadata-file ./metadata.json \
  --output-file ./metadata.json
```

### Add DID service URL

Adds your FAIR service URL to a DID.

```bash
npm run fair-tools -- did service add \
  --did did:plc:xxx \
  --url https://example.com/did:plc:xxx/metadata.json
```

### Replace DID service URL

Replaces the FAIR service URL for a DID. Requires specifying the old URL to prevent accidental overwrites.

```bash
npm run fair-tools -- did service replace \
  --did did:plc:xxx \
  --old-url https://old.example.com/metadata.json \
  --new-url https://new.example.com/metadata.json
```

### Remove DID service URL

Removes the FAIR service URL from a DID. Requires specifying the URL to prevent accidental removals.

```bash
npm run fair-tools -- did service remove \
  --did did:plc:xxx \
  --url https://example.com/metadata.json
```

## DID management

Over time you may need to manage the keys for your DID.

### Add alsoKnownAs URL

Adds a URL to the alsoKnownAs field of a DID. For FAIR domain aliases, use a `fair://` URL.

```bash
npm run fair-tools -- did aka add \
  --did did:plc:xxx \
  --url fair://example.com
```

Before adding a `fair://` alias, ensure your domain has a TXT record at `_fairpm.<domain>` with the value `did=<your-did>`. Use `did domain verify` to check this. After adding the alias, use `did domain verify-alias` to verify the complete setup.

### Replace alsoKnownAs URL

Replaces a URL in the alsoKnownAs field of a DID. Requires specifying the old URL to prevent accidental overwrites.

```bash
npm run fair-tools -- did aka replace \
  --did did:plc:xxx \
  --old-url fair://old.example.com \
  --new-url fair://new.example.com
```

### Remove alsoKnownAs URL

Removes a URL from the alsoKnownAs field of a DID.

```bash
npm run fair-tools -- did aka remove \
  --did did:plc:xxx \
  --url fair://example.com
```

### Verify domain

Verifies that a domain's DNS TXT record is correctly configured for a DID. Use this to check DNS propagation before adding a domain alias to your DID.

```bash
npm run fair-tools -- did domain verify \
  --domain example.com \
  --did did:plc:xxx
```

The domain requires a TXT record at `_fairpm.<domain>` with the value `did=<your-did>`.

### Verify domain alias

Verifies the `fair://` domain alias in a DID's alsoKnownAs field by fetching the DID document, extracting the alias, and checking the corresponding DNS TXT record.

```bash
npm run fair-tools -- did domain verify-alias \
  --did did:plc:xxx
```

### Add verification key

Generates a new verification key, adds it to a DID, and saves it to the key file.

```bash
npm run fair-tools -- did verification-key add \
  --did did:plc:xxx
```

Use `--output-file` to save the new key to a different file instead of the signing file.

### Add rotation key

Generates a new rotation key, adds it to a DID, and saves it to the key file.

```bash
npm run fair-tools -- did rotation-key add \
  --did did:plc:xxx
```

Use `--output-file` to save the new key to a different file instead of the signing file.

### Revoke verification key

Revokes a verification key from a DID.

```bash
npm run fair-tools -- did verification-key revoke \
  --did did:plc:xxx \
  --revoke did:key:z6Mk...
```

Use `--cleanup` to delete the revoked key from the key file after success.

### Revoke rotation key

Revokes a rotation key from a DID.

```bash
npm run fair-tools -- did rotation-key revoke \
  --did did:plc:xxx \
  --revoke did:key:zQ3sh...
```

You cannot revoke the key used to sign the operation, and at least one rotation key must remain.

When using `--signing-file` without `--signing-key`, defaults to signing with the first available rotation key that isn't being revoked.

Use `--cleanup` to delete the revoked key from the key file after success.

## License

MIT
