var express = require("express");
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");
require('dotenv').config();

var jose = require('node-jose');
var jwt = require('jsonwebtoken');

const provider = require('./authenticators/' + process.env.PROVIDER)

var app = express();

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.use("/public", express.static(path.join(__dirname, "public")));

app.set("view engine", "pug");

// Fetch the public keys for verification at startup
var key ;

// Authorize endpoint called from Okta. 
app.get("/authorize", (request, response) => {  
  provider.setNonce(request.query.nonce);
  response.redirect(
    request.query.redirect_uri + "?code=" + request.query.login_hint + "&state=" + request.query.state
  );
});

// Token endpoint called from Okta. Get the signed token for IDP verification
app.post("/token",  async (request, response)  =>  {
  let customToken = await provider.getToken(request.body.code);
  response.send(customToken);
});

// JWKS endpoint called from Okta. Get the public keys for IDP verification 
app.get("/keys", (request, response) => {
  response.send(provider.getKeys());
});

app.get("/", function (request, response) {
  response.render("index", { title: "Hey", message: "This is a Sample OpenID Connect Login Provider!" });
});

app.listen(process.env.PORT || 4000);
