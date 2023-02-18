from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import requests
import json
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask_cors import CORS
import face_recognition
import numpy
import os 

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
THRESHOLD = 2
SECRET = app.secret_key.encode()
server_names = []
indexContent = ""

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# The base URL of the identity provider
IDP_BASE_URL = 'http://localhost:3000'
SP_BASE_URL = 'http://localhost:1111'
    
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

def encrypt_message(base64_public_key, message):
    public_key = base64.b64decode(base64_public_key)
    print("Received public key: ", public_key)
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    return base64.b64encode(encrypted_text)

def parser(status_string, response, jwt_token, threshold):
    global indexContent
    result = []
    if(status_string is False):
      indexContent = response
      return 
    else: 
      server_urls = json.loads(response)
      for i in server_urls:
          server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
          server_key = base64.b64decode(i.split("|")[1]).decode("utf-8")
          username = i.split("|")[2]
          if server_url in server_names:
              result.append('<table style="border:2px solid black;">'+ '<tr>' + '<th>' + '<h3>IP:</h3>' + server_url + '</th>' + '<th>' + '<textarea readonly style="border:double 2px green;" id="print_key" name="key" rows="10" cols="50">' + server_key + '</textarea>' + '</th>' + '</tr>' + '</table>')
      headerToken = '<h2>JWT Token</h2>' + '<table style="border:2px solid black;">'+ '<tr>' + '<th>' + '<h3>Username: ' + username + '</h3>' + '</th>' + '<th>' + '<textarea readonly style="border:double 2px blue;" id="print_key" name="key" rows="10" cols="50">' + jwt_token + '</textarea>' + '</th>' + '</tr>' + '</table>' + "<br>" + '<h2>Trust Servers</h2>'
      indexContent = headerToken
      indexContent += "<br>".join(result)
      return

def checkSign(signature, threshold=2):
    # cycle through the signature list
    global server_names
    signatureList = json.loads(signature)
    for i in signatureList:
        first_param = (i.split("|")[1])
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
        if(first_param != "ERR"):
            base64_key = (i.split("|")[1])
            encrypted_message = encrypt_message(base64_key, SECRET)
            try:
                r = requests.get(
                    f'{server_url+"/sign"}',
                    headers={
                    'message': encrypted_message
                    }
                )
            except:
                print(f"Error, signature from {server_url} NOT received")
                if(server_url in server_names):
                    server_names.remove(server_url)
                continue


            if r.status_code == 200:
                key = r.text
                print("Received key: ", key)
                if(key == SECRET.decode("utf-8")):
                    print(f"Signature from {server_url} received")
                    if(server_url not in server_names):
                        server_names.append(server_url)
                else:
                    print(f"Error, signature from {server_url} NOT received")
                    if(server_url in server_names):
                        server_names.remove(server_url)
            else:
                print(f"Error, server {server_url} is not working, status code: {r.status_code}")
                if(server_url in server_names):
                    server_names.remove(server_url)
        else:
                print(f"Error, signature from {server_url} NOT received")
    print(f"Server signed: {(server_names)}")

    if(len(server_names) >= threshold):
        print("Total servers: ", len(server_names))
        return True
    return False

def checkStatus(r):
  if r.status_code == 200:
    print("Token: ", r.json()['token'])
    # check the signature
    if(checkSign(r.json()['signature'], THRESHOLD)):
        print("JSON: ", r.json())
        token = r.json()['token']
        signature = r.json()['signature']
        u = User(r.json())
        login_user(u)
        ok_string = "<h2>User logged in, signature servers:<h2>"
        parser(ok_string, signature, token, None)
    else:
        ### DA GESTIRE IL LOGIN SE UN UTENTE NON HA LA STESSA FACCIA DELL'ENCODING
        u = User(r.json())
        login_user(u)
        status = False
        err_string = f"<h2>User logged in, but signature servers are not enough. It is required a threshold of {THRESHOLD} servers</h2>"
        parser(status, err_string, None, None)
    return redirect(url_for("index"))
  else:
    return 'Unauthorized: Invalid credentials', 401

def generateEncoding(photo_path):
    # load the user image and get the face encoding
    user_image = face_recognition.load_image_file(photo_path)
    user_face_encoding = face_recognition.face_encodings(user_image)[0]
    # print("Original face encoding: "+str(user_face_encoding))
    # base64_face_encoding = (base64.b64encode(user_face_encoding).decode("ascii"))
    encoded_array = numpy.array2string(user_face_encoding, separator=' ')
    base64_encoded_array = base64.b64encode(encoded_array.encode("ascii"))

    #print("Encoded face encoding: "+base64_encoded_array.decode("ascii"))
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
    global server_names
    server_names.clear()
    logout_user()
    return "User logged out"

@app.route("/")
@login_required
def index():
    global indexContent
    return "<h1 style='text-align:center;'>Trust Identity Chain</h1>" + indexContent

if __name__ == "__main__":
    CORS(app)
    cors = CORS(app, resource={
        r"/*":{
            "origins":"*"
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