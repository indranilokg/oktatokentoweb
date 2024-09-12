const express = require('express');
const app = express();
const path = require('path');
const router = express.Router();
const axios = require('axios');
const qs = require('qs');
const jwt = require('jsonwebtoken');


require('dotenv').config();

app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', __dirname);

app.use(express.urlencoded({extended:true}));

router.get('/',function(req,res){
  res.render('index.html');
});


router.post('/loginNative', async function(req,res){

 let data = qs.stringify({
    'grant_type': 'password',
    'username': req.body.username,
    'password': req.body.password,
    'scope': 'openid' 
  });

  const creds = Buffer.from(process.env.clientId + ":" + process.env.clientSecret).toString('base64');
  console.log(creds);
  
  let config = {
    method: 'post',
    url: process.env.issuer + '/v1/token',
    headers: { 
      'Accept': 'application/json', 
      'Authorization': 'Basic ' + creds, 
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    data : data
  };
  
  const response = await axios.request(config);
  const idToken = jwt.decode(response.data.id_token);
  const accessToken = jwt.decode(response.data.access_token);
  console.log(idToken);
  console.log(accessToken);

  const authenticatedUserData ={username: accessToken.sub, firstname: "Demo", lastname: "User", idToken: response.data.id_token, accessToken: response.data.access_token};
  res.render('profile.html',{authenticatedUserData});
});


//add the router
app.use('/', router);
app.listen(process.env.port || 3000);

console.log('Running at Port 3000');

