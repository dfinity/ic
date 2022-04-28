import {
  Cbor as cbor,
  Certificate,
  HashTree,
  HttpAgent,
  lookup_path,
  reconstruct,
} from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { lebDecode } from '@dfinity/candid';
import { PipeArrayBuffer } from '@dfinity/candid/lib/cjs/utils/buffer';

const MAX_CERT_TIME_OFFSET_IN_MS = 300_000; // 5 min

/**
 * Validate whether a body is properly certified.
 * @param canisterId The canister ID that provided the resource.
 * @param path The path of the resource requested to be validated (including the prefix `/`).
 * @param body An asset body, as it appears on the HTTP response (not decoded)
 * @param certificate The certificate to validate the .
 * @param tree The merkle tree returned by the canister.
 * @param agent A JavaScript agent that can validate certificates.
 * @param shouldFetchRootKey Whether should fetch the root key if it isn't available.
 * @returns True if the body is valid.
 */
export async function validateBody(
  canisterId: Principal,
  path: string,
  body: ArrayBuffer,
  certificate: ArrayBuffer,
  tree: ArrayBuffer,
  agent: HttpAgent,
  shouldFetchRootKey = false
): Promise<boolean> {
  const cert = new Certificate(
    { certificate: new Uint8Array(certificate) },
    agent
  );

  // If we're running locally, update the key manually.
  if (shouldFetchRootKey) {
    await agent.fetchRootKey();
  }

  // Make sure the certificate is valid.
  if (!(await cert.verify())) {
    return false;
  }
  // check certificate time
  if (!validateCertificateTime(cert)) {
    return false;
  }

  const hashTree: HashTree = cbor.decode(new Uint8Array(tree));
  const reconstructed = await reconstruct(hashTree);
  const witness = cert.lookup([
    'canister',
    canisterId.toUint8Array(),
    'certified_data',
  ]);

  if (!witness) {
    throw new Error(
      'Could not find certified data for this canister in the certificate.'
    );
  }

  // First validate that the Tree is as good as the certification.
  if (!equal(witness, reconstructed)) {
    console.error('Witness != Tree passed in ic-certification');
    return false;
  }

  // Next, calculate the SHA of the content.
  const sha = await crypto.subtle.digest('SHA-256', body);
  let treeSha = lookup_path(['http_assets', path], hashTree);

  if (!treeSha) {
    // Allow fallback to `index.html`.
    treeSha = lookup_path(['http_assets', '/index.html'], hashTree);
  }

  if (!treeSha) {
    // The tree returned in the certification header is wrong. Return false.
    // We don't throw here, just invalidate the request.
    console.error(
      `Invalid Tree in the header. Does not contain path ${JSON.stringify(
        path
      )}`
    );
    return false;
  }

  return !!treeSha && equal(sha, treeSha);
}

function validateCertificateTime(cert: Certificate): boolean {
  const decodedTime = lebDecode(new PipeArrayBuffer(cert.lookup(['time'])));
  const certTime = Number(decodedTime / BigInt(1_000_000)); // convert from nanos to millis
  const now = Date.now();
  if (certTime - MAX_CERT_TIME_OFFSET_IN_MS > now) {
    console.error(
      `Invalid certificate: time ${certTime} is too far in the future (current time: ${now})`
    );
    return false;
  }
  if (certTime + MAX_CERT_TIME_OFFSET_IN_MS < now) {
    console.error(
      `Invalid certificate: time ${certTime} is too far in the past (current time: ${now})`
    );
    return false;
  }
  return true;
}

function equal(buf1: ArrayBuffer, buf2: ArrayBuffer): boolean {
  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }

  const a1 = new Uint8Array(buf1);
  const a2 = new Uint8Array(buf2);
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }

  return true;
}
