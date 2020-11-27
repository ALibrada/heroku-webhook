import {Request, RequestHandler} from "express";
import {createHmac} from "crypto";
import {constants} from "http2";

const SIGNATURE_HEADER = "Heroku-Webhook-Hmac-SHA256";

export function verifySignature(req: Request, secret: string): Promise<boolean> {
    const header = req.get(SIGNATURE_HEADER);
    const hmac = createHmac("sha256", secret);
    return new Promise((resolve, reject) => {
        req
            .on("data", (chunk) => hmac.update(chunk))
            .on("end", () => {
                const hash = hmac.digest("base64");
                resolve(header === hash)
            })
            .on("error", err => reject(err))
    })
}

export const verifySignatureMiddleware = (secret: string): RequestHandler => (req, res, next) => {
    const header = req.get(SIGNATURE_HEADER);
    const hmac = createHmac("sha256", secret);
    let body = "";
    req
        .on("data", (chunk) => {
            body += chunk;
            hmac.update(chunk);
        })
        .on("end", () => {
            const hash = hmac.digest("base64");
            if (header === hash) {
                try {
                    const json = JSON.parse(body);
                    req.body = json;
                    next();
                } catch (e) {
                    next(e.message);
                }
            } else {
                res.sendStatus(constants.HTTP_STATUS_FORBIDDEN);
            }
        })
        .on("error", (err) => next(err));
};
