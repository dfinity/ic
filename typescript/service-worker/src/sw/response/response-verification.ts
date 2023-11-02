import {
  VerificationInfo,
  verifyRequestResponsePair,
} from '@dfinity/response-verification';
import {
  HttpRequest,
  HttpResponse,
} from '../../http-interface/canister_http_interface_types';
import { Principal } from '@dfinity/principal';

export const maxCertTimeOffsetNs = BigInt.asUintN(64, BigInt(300_000_000_000));

export function responseVerification(
  httpRequest: HttpRequest,
  httpResponse: HttpResponse,
  minAllowedVerificationVersion: number,
  canisterId: Principal,
  rootKey: ArrayBuffer
): VerificationInfo {
  const currentTimeNs = BigInt.asUintN(64, BigInt(Date.now() * 1_000_000)); // from ms to nanoseconds

  return verifyRequestResponsePair(
    {
      headers: httpRequest.headers,
      method: httpRequest.method,
      url: httpRequest.url,
      body: httpRequest.body,
    },
    {
      statusCode: httpResponse.status_code,
      body: httpResponse.body,
      headers: httpResponse.headers,
    },
    canisterId.toUint8Array(),
    currentTimeNs,
    maxCertTimeOffsetNs,
    new Uint8Array(rootKey),
    minAllowedVerificationVersion
  );
}
