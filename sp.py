from flask import Flask, request, redirect, url_for, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import requests
import json
import base64

app = Flask(__name__)
app.secret_key = 'asdasdasd'  # Change this!
THRESHOLD = 2

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# The base URL of the identity provider
IDP_BASE_URL = 'http://localhost:3000'

    
class User(UserMixin):
    def __init__(self, id):
        self.id = id
    
    def __repr__(self):
        return f"User: {self.id}"

def identify(username, password):
  # Send a request to the identity provider to check the user's credentials
  r = requests.get(
    f'{IDP_BASE_URL}/profile',
    headers={
      'username': username,
      'password': password
    }
  )
  return r

@login_manager.user_loader
def user_loader(user_id):
    user = User(user_id)
    return user

def parser(response):
    result = []
    server_urls = json.loads(response)
    for i in server_urls:
        # print("Ricevuto server: ", i)
        # base64 decode the server url
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
        server_key = base64.b64decode(i.split("|")[1]).decode("utf-8")
        result.append('<table style="border:2px solid black;">'+ '<tr>' + '<th>' + server_url + '</th>' + '<th>' + '<textarea readonly style="border:double 2px green;" id="print_key" name="key" rows="10" cols="50">' + server_key + '</textarea>' + '</th>' + '</tr>' + '</table>')

    return "<br>".join(result)

def checkSign(signature, threshold=2):
    # cycle through the signature list
    server_names = []
    signatureList = json.loads(signature)
    for i in signatureList:
        # print(f"Signature: {sign}")
        base64_key = (i.split("|")[1])
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")

        try:
            r = requests.get(
                f'{server_url}',
                headers={
                'signature': "sign"
                }
            )
        except:
            print(f"Error, signature from {server_url} NOT received")
            continue
        if r.status_code == 200:
            # print(r.json())
            key = r.json().split("|")[1]
            ### non si deve controllare ad ogni richiesta, ma per semplicità lo facciamo
            if(key == base64_key):
                print(f"Signature from {server_url} received")
                server_names.append(server_url)
        else:
            print(f"Error, signature from {server_url} NOT received")
    print(f"Server signed: {(server_names)}")

    if(len(server_names) >= threshold):
        print("Total servers: ", len(server_names))
        return True
    return False

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get the username and password values from the form
        username = request.form["username"]
        password = request.form["password"]

        r = identify(username, password)
        if r.status_code == 200:
            # check the signature
            if(checkSign(r.json()['signature'], THRESHOLD)):
                u = User(r.json())
                login_user(u)
                return f"<h2>User logged in, signature servers:<h2> <h3>{parser(r.json()['signature'])}</h3>"
            else:   
                return f"<h2>User logged in, but signature servers are not enough. It is required a thresold of {THRESHOLD} servers</h2>"

        else:
            return 'Unauthorized: Invalid credentials', 401

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    # Otherwise, show the login page
    return """
        <form action="" method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    """

@app.route("/logout")
def logout():
    logout_user()
    return "User logged out"

@app.route("/")
@login_required
def index():
    return "Home page"

if __name__ == "__main__":
    app.run()