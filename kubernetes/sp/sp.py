from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import requests
import json
import base64
from flask_cors import CORS
import face_recognition
import numpy
import os 
from jwtoken import verify_aggregate_signature, base64url_decode
from blspy import G1Element, G2Element

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

try:
        THRESHOLD = os.environ['SERVER_THRESHOLD']
except:
        THRESHOLD = 2
        
SECRET = app.secret_key.encode()
valid_servers = []
indexContent = ""

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# The base URL of the identity provider
IDP_BASE_URL = 'http://idp:3000'
SP_BASE_URL = 'http://sp:1111'
    
class User(UserMixin):
    def __init__(self, id):
        self.id = id
    
    def __repr__(self):
        return f"User: {self.id}"

def identify_password(username, password):
  # Send a request to the identity provider to check the user's credentials
  r = requests.get(
    f'{IDP_BASE_URL}/profile',
    headers={
      'username': username,
      'password': password,
    }
  )
  return r

#send request to check if attempt face matches with user known face
def identify_face(username, encoding):
    r = requests.get(
    f'{IDP_BASE_URL}/profile',
    headers={
      'username': username,
      'encoding': encoding,
      'threshold': str(THRESHOLD)
    }
    )
    print(str(r))
    return r

@login_manager.user_loader
def user_loader(user_id):
    user = User(user_id)
    return user

def parser(status, status_string, response, jwt_token):
    global indexContent
    result = []
    if(status is False):
      print("ERROR")
      indexContent = status_string
      return 
    else: 
      server_urls = json.loads(response)
      for i in server_urls:
          server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
          base64_pk = i.split("|")[2]
          base64_pop = i.split("|")[3]
          pk = G1Element.from_bytes(base64url_decode(base64_pk))
          pop = G2Element.from_bytes(base64url_decode(base64_pop))
          username = i.split("|")[4]
          if server_url in valid_servers:
              result.append('<table style="border:2px solid black;">'+ '<tr>' + '<th>' + server_url + '</th>' + '<th>' + '<textarea readonly style="border:double 2px green;" id="print_key" name="key" rows="10" cols="50">' + "Public Key:\n" + str(pk) + "\n\nProof of Possession:\n" + str(pop) + '</textarea>' + '</th>' + '</tr>' + '</table>')
      headerToken = '<h2>JWT Token</h2>' + '<table style="border:2px solid black;">'+ '<tr>' + '<th>' + '<h3>Username: ' + username + '</h3>' + '</th>' + '<th>' + '<textarea readonly style="border:double 2px blue;" id="print_key" name="key" rows="10" cols="50">' + jwt_token + '</textarea>' + '</th>' + '</tr>' + '</table>' + "<br>" + '<h2>Trust Servers</h2>'
      indexContent = headerToken
      indexContent += "<br>".join(result)
      return

def checkSign(signature):
    # cycle through the signature list
    global valid_servers
    pk_list = []
    valid_servers = []
    valid = False
    verified = False
    signatureList = json.loads(signature)
    print("Signature list: ", signatureList)
    for i in signatureList:
        first_param = (i.split("|")[1])
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
        if(first_param != "ERR"):
            base64_token = (i.split("|")[1])
            decoded_token = base64url_decode(base64_token)
            #decoded_token = base64.b64decode(base64_token).decode("utf-8")
            token_bytes = bytes(decoded_token)
            print("Received token: ", decoded_token)
            try:
                r = requests.get(
                    f'{server_url+"/sign"}',
                )
            except:
                print(f"Error, signature from {server_url} NOT received")

            print(r.status_code)
            if r.status_code == 200:
                base64_pk = r.text.split("|")[0]
                pk = G1Element.from_bytes(base64url_decode(base64_pk))
                pk_list.append(pk)
                print("Received key: ", pk)  
                valid_servers.append(server_url)
                if(len(pk_list) == len(signatureList)):
                    print(f"List of public keys: {pk_list}")
                    verified = verify_aggregate_signature(pk_list, token_bytes)
                    if(verified):  
                        valid = True
                    else:
                        print(f"Error, signature from {server_url} NOT received")
            else:
                print(f"Error, server {server_url} is not working")

        else:
                print(f"Error, signature from {server_url} NOT received")
    print(f"Valid servers: {valid_servers}, valid: {valid}")
    if(valid):
        print("Total servers: ", len(valid_servers))
        return True
    return False

def checkStatus(r):
  if r.status_code == 200:
    # check the signature
    if(checkSign(r.json()['signature'])):
        print("JSON: ", r.json())
        token = r.json()['token']
        signature = r.json()['signature']
        u = User(r.json())
        login_user(u)
        ok_string = "<h2>User logged in, signature servers:<h2>"
        status = True
        parser(status, ok_string, signature, token)
    else:
        if(r.json()['signature'].split("|")[1] == "ERR"):
            print("Error, faces are not the same")
            return redirect(url_for("index"))
        u = User(r.json())
        login_user(u)
        status = False
        err_string = "<h2>User logged in, but there are no servers that can sign your token</h2>"
        parser(status, err_string, None, None)
    return redirect(url_for("index"))
  else:
    return 'Unauthorized: Invalid credentials', 401

def generateEncoding(photo_path):
    # load the user image and get the face encoding
    user_image = face_recognition.load_image_file(photo_path)
    user_face_encoding = face_recognition.face_encodings(user_image)[0]
    print("Encoding: "+str(user_face_encoding))
    encoded_array = numpy.array2string(user_face_encoding, separator=' ')
    base64_encoded_array = base64.b64encode(encoded_array.encode("ascii"))
    return base64_encoded_array.decode("ascii")

@app.route("/loginpassword", methods=["GET", "POST"])
def login_password():
    if request.method == "POST":
            # Get the username and password values from the form
            username = request.form["username"]
            password = request.form["password"]

            r = identify_password(username, password)
            return checkStatus(r)
           
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

#send request to check if attempt face match with known user face
@app.route("/facesend", methods=["GET", "POST"])
def face_send():
    try:
        username = request.headers.get('username')
        photo_path = f'{username}.jpg'
        data = request.get_data()
        with open(photo_path, 'wb') as f:
            f.write(data)
        encoding = generateEncoding(photo_path)
        r = identify_face(username, encoding)
        os.remove(photo_path)
    except:
        print("Error, face not sent")
        os.remove(photo_path)
        return 'Unauthorized: Invalid credentials', 401
    return checkStatus(r)

#logout and destroy session
@app.route("/logout")
def logout():
    global valid_servers
    valid_servers.clear()
    logout_user()
    return "User logged out"

#user home page (only visible when logged in)
@app.route("/")
@login_required
def index():
    global indexContent
    return "<h1 style='text-align:center;'>Trust Identity Chain</h1>" + indexContent
    
# run with 127.0.0.1 because CORS works only with this address
if __name__ == "__main__":
    CORS(app)
    cors = CORS(app, resource={
        r"/*":{
            "origins":"*",
            "Access-Control-Allow-Origin:": "*"
        }
    })
    app.run()

#return login page with face sending
@app.route("/loginface")
def login_face():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return """
    <html>
    <head>
        <title>Webcam Upload</title>
        <style>
            html, body {
                height: 100%;
            }
            * {
                font-family: sans-serif;
                user-select: none;
            }
            canvas {
                border: 1px solid black;
                float: left;
            }
            body, #two-up {
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            button {
                margin: 1em;
                font-size: 120%;
            }
        </style>
    </head>
    <body>
        <script>
            function cameraReady(videoElement) {
                console.log('cameraReady: checking...');
                if (videoElement) {
                    if (videoElement.srcObject) {
                        let tracks = videoElement.srcObject.getVideoTracks();
                        if (tracks.length > 0) {
                            if (tracks[0].readyState == 'live') {
                                let w = videoElement.videoWidth, h = videoElement.videoHeight;
                                if (w > 0 || h > 0) {
                                    console.log('cameraReady: live! ' + w + 'x' + h);
                                    return true;
                                }
                                console.error('cameraReady: live, but 0x0');
                                return false;
                            }
                            console.error('cameraReady: readyState is ' + tracks[0].readyState);
                            return false;
                        }
                        console.error('cameraReady: no tracks');
                        return false;
                    }
                    console.error('cameraReady: no srcObject');
                    return false;
                }
                console.error('cameraReady: no element');
                return false;
            }
            
            function initCamera(videoElement) {
                // these are essential on iOS
                videoElement.setAttributeNode(document.createAttribute('autoplay'));
                videoElement.setAttributeNode(document.createAttribute('playsinline'));
                
                // don't re-initialize the camera if it's already live
                if (cameraReady(videoElement)) {
                    console.log('initCamera: done!');
                    return Promise.resolve();
                }
                
                return navigator.mediaDevices
                .getUserMedia({
                    audio: false,
                    video: { facingMode: 'user' }
                })
                // stream is ready, set to the video element
                // don't return until the metadata is ready
                // https://stackoverflow.com/a/41866914/940196
                .then(stream => new Promise(resolve => {
                    console.log('initCamera: setting srcObject...');
                    videoElement.onloadedmetadata = resolve;
                    videoElement.srcObject = stream;
                }))
                .then(() => console.log('initCamera: done!'))
                .catch(err => {
                    console.error(err);
                    alert(config.cameraErrorMessage);
                })
            }
            
            window.onload = (event) => {
                let videoElt = document.getElementById('camera');
                initCamera(videoElt);
            };
            
            function videoToBlob(src, cb) {
                let width = src.videoWidth || src.width;
                let height = src.videoHeight || src.height;
                let canvas = new OffscreenCanvas(width, height);
                let ctx = canvas.getContext('2d');
                ctx.drawImage(src, 0, 0, width, height);
                canvas.convertToBlob({
                    type: 'image/jpeg',
                    quality: 0.80
                }).then(blob => {
                    cb(blob);
                });
            }
            
            function upload() {
                let src = document.getElementById('camera');
                let username = document.getElementById('username').value;
                username = username.replace(/\//g, '');
                if (username != '') {
                videoToBlob(src, blob => {
                    let url = 'http://127.0.0.1:1111/facesend';
                    fetch(url, {
                        method: 'post',
                        mode: 'cors',
                        headers: {
                          'Content-Type': 'application/json',
                          'Access-Control-Allow-Origin': "*",
                          'username': username
                        },
                        body: blob
                    }).then(response => response.json())
                    .then(data => console.log(data))
                });
                }
            }
        </script>
        <div>
            <video id="camera" style="cursor:pointer"></video>
            <form id="login">
              <input type="text" id="username" name="username" placeholder="Username">
              <button id="login" onclick="upload()">Accedi</button>
            </form>

        </div>
        
    </body>
    </html>"""