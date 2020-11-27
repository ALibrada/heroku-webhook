import express from "express";
import {verifySignature, verifySignatureMiddleware} from "./index";
import {constants} from "http2";

const PORT = process.env.PORT || "3000";
const APP_SECRET = process.env.WEBHOOK_SECRET;
const app = express();

app.post("webhook", async (req, res) => {
    const isVerified = await verifySignature(req, APP_SECRET);
    if(isVerified) {
        res.sendStatus(constants.HTTP_STATUS_ACCEPTED)
    }
    res.sendStatus(constants.HTTP_STATUS_FORBIDDEN);
});

app.post("webhook-middleware", verifySignatureMiddleware(APP_SECRET), (req, res) => {
    res.send(req.body)
})
app.listen(PORT, () => console.log(`Listening on ${PORT}`));
