export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export interface WalletSigner {
  connect(): Promise<string>;
  signMessage(hash: string): Promise<string>;
  getAddress(): string | null;
}

export class InjectedWalletSigner implements WalletSigner {
  private address: string | null = null;
  constructor(private readonly provider: Eip1193Provider) {}
  async connect(): Promise<string> {
    const accounts = await this.provider.request({ method: "eth_requestAccounts" });
    const account = Array.isArray(accounts) ? accounts[0] : undefined;
    if (typeof account !== "string") throw new Error("No wallet account was returned.");
    this.address = account;
    return account;
  }
  async signMessage(hash: string): Promise<string> {
    const address = this.address ?? await this.connect();
    const result = await this.provider.request({ method: "personal_sign", params: [hash.startsWith("0x") ? hash : `0x${hash}`, address] });
    if (typeof result !== "string") throw new Error("Wallet did not return a signature.");
    return result;
  }
  getAddress(): string | null { return this.address; }
}

export function getInjectedSigner(): WalletSigner | null {
  const provider = (window as Window & { ethereum?: Eip1193Provider }).ethereum;
  return provider ? new InjectedWalletSigner(provider) : null;
}
