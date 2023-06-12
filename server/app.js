const express = require('express')
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const { MongoClient } = require("mongodb");

const app = express();
let url = 'mongodb://localhost:27017/';
app.set('view engine', 'ejs');
const port = 3000;
const client = new MongoClient(url);
const db = client.db("oauth");

app.use((req,res,next)=>{
    res.header('Access-Control-Allow-Origin','*');
    next()
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({secret: uuidv4(),saveUninitialized: true,resave: true,cookie: {expires: 2678400000}}));
let auth_codes = [];

//set middle ware to api endpoints only
async function checkToken(req,res,next){
    client_id = req.body.client_id;
    cursor = await db.collection('clients').findOne({client_id: client_id});
    console.log(JSON.stringify(cursor));
    if(req.body.access_token != cursor.token){
        console.log('check token failed');
        return res.json({error: "invalid_token"});
    }
    next();
}

app.post('/oauth/api/data', checkToken, (req, res) => {
    return res.json({email: "adminuser@server.com",username: "adminuser"});
});

app.get('/oauth/login', (req, res) => {
    if(req.session.loggedin){
        // TODO: we have to implement to send and check if authorized button is clicked
        var code = uuidv4().toString().replace(/-/g, "");
        auth_codes.push({client_id: req.session.client_id, auth_code: code});
        return res.redirect(req.session.redirect_uri + "?code="+code+"&state=" + req.session.state);
    }
    res.render('login',{scope: req.session.scope});
});

app.post('/oauth/login', (req, res) => {
    var code = uuidv4().toString().replace(/-/g, "");
    var user = req.body.user;
    var pass = req.body.pass;
    var authorize = req.body.authorize;
    // TODO: implement an actual authentication -_(-_-)_-
    if(user=="admin" && pass=="admin"){
        req.session.loggedin = true;
        if(authorize){
            auth_codes.push({client_id: req.session.client_id, auth_code: code});
           return res.redirect(req.session.redirect_uri + "?code="+code+"&state=" + req.session.state);
        }
        return res.render('login', {scope: req.session.scope});
    }
    return res.render('login', {scope: req.session.scope});
});

app.post('/oauth/token', async (req, res) => {
    var grant_type = req.body.grant_type;
    var code = req.body.code;
    var redirect_uri = req.body.redirect_uri;
    var client_id = req.body.client_id;
    var client_secret = req.body.client_secret;
    // check if the client id and client secret are valid add mongodb check instead of hardcode
    if(client_id == "9ebea9bd56ad4f52a0d032a07d459d79" && client_secret == "809bac3928114e89bd5e1df9d66b12d0"){
        if(grant_type == "authorization_code"){
            for(var codes of auth_codes){
                if(code == codes.auth_code && client_id == codes.client_id){
                    var access_token = uuidv4().toString().replace(/-/g, "");
                    var refresh_token = uuidv4().toString().replace(/-/g, "");
                    var expiry_date = new Date();
                    expiry_date.setSeconds(expiry_date.getSeconds() + 3600);
                    // save the values in session X <= this way was dump so now we gonna save it in mongodb
                    await db.collection('clients').updateOne({client_id: client_id},{"$set":{token: access_token,rtoken: refresh_token}},(err,result)=>{
                        if(err) throw err;
                    })
                    req.session.expiry_date = expiry_date;
                    
                    return res.json({access_token: access_token, refresh_token: refresh_token});
                }
            }
        }
    }
    return res.json({error: "invalid_grant"});
});

app.get('/oauth', (req, res) => {
    // get all the values from the client oauth query string
    var client_id = req.query.client_id;
    var response_type = req.query.response_type;
    var redirect_uri = req.query.redirect_uri;
    var scope = req.query.scope;
    var state = req.query.state;
    // save the values in session
    req.session.client_id = client_id;
    req.session.response_type = response_type;
    req.session.redirect_uri = redirect_uri;
    req.session.scope = scope;
    req.session.state = state;
    res.redirect("/oauth/login");
});

app.get("/clients/register",(req,res)=>{
    return res.render('register');
});
// TODO: regex check for matching proper URI's
app.post("/clients/register",async (req,res)=>{
    client_uri = req.body.uri;
    client_name = req.body.client_name;
    client_id = uuidv4().toString().replace(/-/g, "");
    client_secret = uuidv4().toString().replace(/-/g, "");
    if(typeof client_uri != 'string' || typeof client_name != 'string'){
        return res.send({info: "Aborted: Invalid input"})
    }
    cursor = await db.collection('clients').findOne({client_uri: client_uri});
    if(!client_uri){
        return res.send({info: "Aborted: PLease specify a redirect URI"})
    }
    if(cursor){
        return res.send({info: "Aborted: Client already exists"})
    }
    await db.collection('clients').insertOne({client_name: client_name,client_id: client_id,client_secret: client_secret,client_uri: client_uri.toString(),token: '',rtoken: ''},
    (err,result)=>{
        if(err) throw err;
        console.log(`This is the result of insert in mongodb: ${result}`);
    });
    return res.send({client_id: client_id,client_secret: client_secret,info: "PLease save this values"})
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
    }
);