import express from "express";
import { createHmac } from "crypto";

const PORT = process.env.PORT || "3000";
const APP_SECRET = process.env.WEBHOOK_SECRET;
const app = express();

const SIGNATURE_HEADER = "Heroku-Webhook-Hmac-SHA256";

app.use(function (req, res, next) {
  const header = req.get(SIGNATURE_HEADER);
  const hmac = createHmac("sha256", APP_SECRET);
  req
    .on("data", (chunk) => hmac.update(chunk))
    .on("end", () => {
      const hash = hmac.digest("base64");
      if (header === hash) {
        next();
      } else {
        res.sendStatus(403);
      }
    });
});

app.post("webhook", (req, res) => {
  console.log(req.body);
  res.sendStatus(204);
});
app.listen(PORT, () => console.log(`Listening on ${PORT}`));
