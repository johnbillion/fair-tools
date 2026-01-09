/**
 * Display utilities for release verification results.
 */

interface VerifiedArtifact {
	url: string;
	signatureValid: boolean;
	checksumValid: boolean;
	keyId: string | null;
}

interface VerifiedRelease {
	version: string;
	artifacts: VerifiedArtifact[];
}

/**
 * Display release verification details.
 */
export function displayReleases(releases: VerifiedRelease[], failed = false): void {
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
