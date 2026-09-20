declare module "@mstblockchain/mst-sdk" {
  export class Client {
    constructor(rpcUrl: string, privateKey: string);
    readonly provider: unknown;
    readonly signer: unknown;
  }
}
