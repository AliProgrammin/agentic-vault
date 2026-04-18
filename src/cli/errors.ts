export const EXIT_OK = 0;
export const EXIT_USER = 1;
export const EXIT_AUTH = 2;
export const EXIT_INTERNAL = 3;

export class CliError extends Error {
  public override readonly name = "CliError";
  public readonly exitCode: number;

  public constructor(exitCode: number, message: string) {
    super(message);
    this.exitCode = exitCode;
  }
}
