export class MalformedCanisterError extends Error {
  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class MalformedHostnameError extends Error {
  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class CurrentGatewayResolveError extends Error {
  constructor() {
    super(`Fail to resolve gateway for current location.`);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
