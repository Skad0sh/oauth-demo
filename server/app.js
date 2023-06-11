const express = require('express')
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.set('view engine', 'ejs');
const port = 3000;

app.use((req,res,next)=>{
    res.header('Access-Control-Allow-Origin','*');
    next()
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({secret: uuidv4(),saveUninitialized: true,resave: true,cookie: {expires: 2678400000}}));

//set middle ware to api endpoints only
function checkToken(req,res,next){
    if(req.body.access_token != req.session.token){
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
        req.session.code = code;
        console.log("session: "+req.session.code);
        console.log("session_full: "+JSON.stringify(req.session));
        console.log("query: "+code);
        return res.redirect(req.session.redirect_uri + "?code="+code+"&state=" + req.session.state);
    }
    res.render('login',{scope: req.session.scope});
});

app.post('/oauth/login', (req, res) => {
    var code = uuidv4().toString().replace(/-/g, "");
    var user = req.body.user;
    var pass = req.body.pass;
    var authorize = req.body.authorize;

    if(user=="admin" && pass=="admin"){
        req.session.loggedin = true;
        if(authorize){
            // write code to create an oauth authorization code
            req.session.code = code;
            console.log("session: "+req.session.code);
            console.log("session_full: "+JSON.stringify(req.session));
            console.log("query: "+code);
           return res.redirect(req.session.redirect_uri + "?code="+code+"&state=" + req.session.state);
        }
        return res.render('login', {scope: req.session.scope});
    }
    return res.render('login', {scope: req.session.scope});
});
// why is session token undefined here?

app.post('/oauth/token', (req, res) => {
    // get all the values from the client token query string
    var grant_type = req.body.grant_type;
    var code = req.body.code;
    var redirect_uri = req.body.redirect_uri;
    var client_id = req.body.client_id;
    var client_secret = req.body.client_secret;
    // check if the client id and client secret are valid
    if(client_id=="secret" && client_secret=="verysecret"){
        console.log('check 1');
        if(grant_type=="authorization_code"){
            console.log('check 2');
            console.log("session: "+JSON.stringify(req.session));
            if(code==req.session.code){
                console.log('check 3');
                // create an access token
                var access_token = uuidv4().toString().replace(/-/g, "");
                // create a refresh token
                var refresh_token = uuidv4().toString().replace(/-/g, "");
                // create an expiry date
                var expiry_date = new Date();
                expiry_date.setSeconds(expiry_date.getSeconds() + 3600);
                // save the values in session
                req.session.access_token = access_token;
                req.session.refresh_token = refresh_token;
                req.session.expiry_date = expiry_date;
                // return the access token and refresh token
                return res.json({access_token: access_token, refresh_token: refresh_token});
            }
        }
    }
    // return error
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

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
    }
);