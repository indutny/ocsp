// https://github.com/indutny/ocsp
declare module "ocsp" {
    import * as Http from "http";
    import * as Https from "https";

    // https://github.com/indutny/ocsp#agent
    class Agent extends Https.Agent {
        constructor(opts?: AgentOptions);
    }

    interface AgentOptions extends Https.AgentOptions {
        CACacheSize?: number
    }

    // https://github.com/indutny/ocsp#cache
    class Cache {
        constructor(options?: { probe?: () => any, store?: () => any, filter?: (url: string, callback: () => any) => any });

        request(id: string | Buffer, options: { url: string, ocsp: Buffer }, cb: (err: Error | null, resp: Buffer) => any): void

        probe(id: string, cb: (error: Error, cached: { response: any, timer: NodeJS.Timeout } | false) => any): void
    }


    // https://github.com/indutny/ocsp#server
    let Server: IServer;

    interface IServer {

        create(param: {
            cert: string | Buffer,
            key: string | Buffer
        }): ExtServer
    }


    interface ExtServer extends Http.Server {
        addCert(serialNumber: number, status: "good" | "revoked", info?: {
            revocationTime?: Date,
            revocationReason?: "unspecified"
                | "keyCompromise"
                | "CACompromise"
                | "affiliationChanged"
                | "superseded"
                | "cessationOfOperation"
                | "certificateHold"
                | "removeFromCRL"
                | "privelegeWithdrawn"
                | "AACompromise"
        }): void
    }


    // https://github.com/indutny/ocsp#check
    function check(options: {
        cert: string | Buffer,
        issuer: string | Buffer
    }, cb: (err: Error, res: Http.ServerResponse) => any): void


    // https://github.com/indutny/ocsp#verify
    function verify(options: {
        request: Http.IncomingMessage,
        response: Http.ServerResponse,
        issuer?: string | Buffer
    }, cb: (err: Error, res: Http.ServerResponse) => any): void


    // https://github.com/indutny/ocsp#requestgenerate
    let request: IRequest;

    interface IRequest {
        generate(
            cert: string | Buffer,
            issuerCert: string | Buffer): Req
    }

    interface Req extends Http.IncomingMessage {
        id: Buffer,
        certID: any,
        data: any,
        cert: Buffer,
        issuer: Buffer
    }

    // https://github.com/indutny/ocsp#getocspuri
    function getOCSPURI(
        cert: string | Buffer,
        cb: (err: Error | null, uri?: string | null) => any): void
}
