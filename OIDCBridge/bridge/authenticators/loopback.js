const axios = require("axios");

require('dotenv').config();

var jose = require('node-jose');
var jwt = require('jsonwebtoken');

var customJWK  = null;
var customKeystore = null;
var publicKey = null;
var privateKeyPEM = null;
var publicKeyPEM = null;
var customNonce = null;


 // Perform authentication 
 // Okta - Get the ID Token
exports.validateLogin = async (username, password) => {
  try {
    let data = process.env.CLIENT_ID + ":" + process.env.CLIENT_SECRET ;
    let buff = Buffer.from(data);
    let encodedSecret = buff.toString("base64");

    const options = {
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        authorization: "Basic " + encodedSecret,
      },
    };
    payload = {
      username: username,
      password: password,
      grant_type: "password",
      scope: "openid email profile",
    };

    let qs = new URLSearchParams(payload)

    result = await axios.post(
      process.env.BASE_URL + "/oauth2/v1/token",
      qs.toString(),
      options
    );
    
    return result.data.id_token;

  } catch (error) {
    throw error;
  }
};


// Return public key for token validation
exports.getKeys = () => {
  let keys = {"keys":[publicKey]}
  console.log(JSON.stringify(keys));
  return JSON.stringify(keys);
};

// Return ID token for Inbound IDP verification
exports.getToken =  async (token) => {

    let originalClaims = jwt.decode(token);
    let claims = {};
    claims.nonce =  customNonce;
    claims.sub =  originalClaims.sub;
    claims.ver =  originalClaims.ver;
    claims.iss =  originalClaims.iss;
    claims.aud =  originalClaims.aud;
    claims.email =  originalClaims.sub;
    console.log(claims);

    customKeystore = jose.JWK.createKeyStore();
    let result = await customKeystore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' });
    publicKey  = result.toJSON();
    privateKeyPEM  = result.toPEM(true);
    publicKeyPEM  = result.toPEM(false);
    customJWK= jwt.sign(claims,privateKeyPEM,
      { 
        algorithm: 'RS256',
        header:
          {
            typ: 'jwt'
          }
      }
    );
    var responseData = {
      access_token: customJWK,
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid",
      id_token: customJWK,
    };
    return responseData;
  };


  exports.setNonce =  (nonce) => {
    customNonce = nonce;
  };