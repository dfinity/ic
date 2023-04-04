export class NotAllowedRequestRedirectError extends Error {
  constructor() {
    super(
      'Due to security reasons redirects are blocked on the IC until further notice!'
    );
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
