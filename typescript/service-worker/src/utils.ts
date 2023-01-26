export function getValueFromCookie(
  name: string,
  cookie = document.cookie
): string | null {
  return cookie.match(new RegExp(`(?:${name}=)(.*?)(?:;|$)`))?.[1] ?? null;
}

export async function hashString(
  str: string,
  algorithm = 'SHA-256'
): Promise<string> {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function parseSafeInteger(value?: string, radix = 10): number {
  if (!value) {
    return NaN;
  }

  const parsedNumber = Number.parseInt(value, radix);
  if (
    !Number.isNaN(parsedNumber) &&
    parsedNumber >= Number.MIN_SAFE_INTEGER &&
    parsedNumber <= Number.MAX_SAFE_INTEGER
  ) {
    return parsedNumber;
  }

  return NaN;
}
