export class Logger {
  public info<T>(message: T, ...args: unknown[]): void {
    console.log(message, ...args);
  }

  public warn<T>(message: T, ...args: unknown[]): void {
    console.warn(message, ...args);
  }

  public error<T>(message: T, ...args: unknown[]): void {
    console.error(message, ...args);
  }

  public debug<T>(message: T, ...args: unknown[]): void {
    console.debug(message, ...args);
  }
}

export default new Logger();
