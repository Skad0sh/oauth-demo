from flask import Flask,render_template,request,session,redirect
import requests
import uuid

app = Flask(__name__)
app.secret_key = str(uuid.uuid4()).replace("-","")

@app.route("/",methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if(session.get("access_token")):
        r = requests.post("http://localhost:3000/oauth/api/data",data={"access_token":session["access_token"]})
        username = r.json()["username"]
        email = r.json()["email"]
        session["username"] = username
        session["email"] = email
        session["logged_in"] = True
        return render_template("dashboard.html",username=username,email=email)

    state_token = str(uuid.uuid4()).replace("-","")
    session["state"] = state_token
    return render_template("login.html",state_token=state_token)

@app.route("/callback",methods=["GET"])
def callback():
    code = request.args.get("code").strip()
    state = request.args.get("state")
    if(state == session["state"]):
        print("fine")
        r=requests.post("http://localhost:3000/oauth/token",data={"code":code,"client_secret":"verysecret","client_id":"secret","redirect_uri":"http://localhost:5000/callback","grant_type":"authorization_code"})
        if(r.json().get("error")):
            return {"code":code,"state":state}
        token = r.json()["access_token"]
        session["access_token"] = token
        print(r.json())
        # return redirect("/login")
    return {"code":code,"state":state}

if __name__ == "__main__":
    app.run(port=5000,debug=True)