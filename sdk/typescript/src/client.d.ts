export class PhoenixError extends Error {
  status: number;
  constructor(message: string, status?: number);
}

export interface ResolveResult {
  values: Record<string, string>;
  errors?: Record<string, string>;
}

export interface PhoenixClientOptions {
  server?: string;
  token?: string;
  timeout?: number;
  sealKeyPath?: string;
}

export class PhoenixClient {
  server: string;
  token: string;
  timeout: number;

  constructor(options?: PhoenixClientOptions);

  setSealKey(path: string): Promise<void>;
  health(): Promise<Record<string, unknown>>;
  resolve(ref: string): Promise<string>;
  resolveBatch(refs: string[]): Promise<ResolveResult>;
}
