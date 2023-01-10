export function getValueFromCookie(
  name: string,
  cookie = document.cookie
): string | null {
  return cookie.match(new RegExp(`(?:${name}=)(.*?)(?:;|$)`))?.[1] ?? null;
}
