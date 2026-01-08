/**
 * Display utilities for release verification results.
 */

/**
 * Display release verification details.
 * @param {object[]} releases
 * @param {boolean} [failed=false] - Whether the releases are from a failed verification
 */
export function displayReleases(releases, failed = false) {
	for (const release of releases) {
		const icon = failed ? '✗' : '✓';
		console.log(`\n${icon} Release v${release.version}`);

		for (const artifact of release.artifacts) {
			const sigStatus = artifact.signatureValid ? `Signature valid (${artifact.keyId})` : 'Signature FAILED';
			const checksumStatus = artifact.checksumValid ? 'checksum valid' : 'checksum FAILED';
			const artifactIcon = artifact.signatureValid && artifact.checksumValid ? '✓' : '✗';
			console.log(`  ${artifactIcon} ${artifact.url}: ${sigStatus}, ${checksumStatus}`);
		}
	}
}
