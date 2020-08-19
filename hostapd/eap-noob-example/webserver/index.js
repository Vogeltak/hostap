const express = require("express");
const app = express();
const https = require('https');
const fs = require('fs');
const DATABASE_PATH = "/tmp/noob_server.db";

var sqlite3 = require("sqlite3").verbose();

var key = fs.readFileSync("./private.pem");
var cert = fs.readFileSync("./certificate.pem");
var options={
  key:key,
  cert:cert
};

app.get("/", (req, res) => {
  res.send(
    "This is a simple webserver for deliverying the OOB message. Please invoke /sendoob/<oobString> to deliver an OOB"
  );
});

app.get("/sendoob/:oobstring", (req, res) => {
  var server_db = new sqlite3.Database(DATABASE_PATH);
  var oobString = req.params.oobstring;
  let buff = Buffer.from(oobString, "base64");
  let text = buff.toString();
  let jsonOob = JSON.parse(text);
  console.log(jsonOob)
  server_db.all(
    "Select * from EphemeralNoob where PeerId = ?",
    [jsonOob.PeerId],
    (err, rows) => {
      let replaced = rows.length > 0;

      server_db.run(
        "Delete from EphemeralNoob where PeerId = ?",
        [jsonOob.peer_id],
        (err) => {
          server_db.run(
            "INSERT INTO EphemeralNoob (PeerId, NoobId, Noob, Hoob, sent_time) VALUES(?,?,?,?,?)",
            [
              jsonOob.peer_id,
              jsonOob.noob_id,
              jsonOob.noob,
              jsonOob.hoob,
              jsonOob.sent_time,
            ],
            (err) => {
              if (!err)
                res.send(
                  replaced ? "Replaced existing oob" : "Inserted new oob"
                );
              else res.send(err);
            }
          );
        }
      );
    }
  );
});

var server = https.createServer(options,app);

server.listen(443, () =>
  console.log("Simple OOB delivery server listening on 3000")
);
