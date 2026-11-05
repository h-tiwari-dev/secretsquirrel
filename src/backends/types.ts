export interface Backend {
  readonly id: string;
  /** Human label shown in the wizard and popups. */
  readonly label: string;
  /** Is the underlying CLI installed and usable? */
  available(): Promise<boolean>;
  /** Names only. Never values. */
  list(): Promise<string[]>;
  get(name: string): Promise<string | undefined>;
  set(name: string, value: string): Promise<void>;
}

/** Env var style names only: keeps argv, shells and backends safe from agent-supplied junk. */
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function assertValidName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new Error(`Invalid secret name "${name}". Use an environment variable name like GITHUB_TOKEN.`);
  }
}

export function assertValidValue(value: string): void {
  if (value.length === 0) throw new Error("Empty secret value.");
  if (/[\r\n\0]/.test(value)) throw new Error("Secret values containing newlines or NUL are not supported.");
}
