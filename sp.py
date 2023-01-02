from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import requests
import json
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
THRESHOLD = 2
SECRET = b'test'
server_names = []

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

def identify_photo(photo):
    # Send a request to the identity provider to check the user's credentials
    r = requests.get(
        f'{IDP_BASE_URL}/profile',
        headers={
        'photo': photo
        }
    )
    return r

@login_manager.user_loader
def user_loader(user_id):
    user = User(user_id)
    return user

def encrypt_message(base64_public_key, message):
    public_key = base64.b64decode(base64_public_key)
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    return base64.b64encode(encrypted_text)

def parser(response):
    result = []
    server_urls = json.loads(response)
    for i in server_urls:
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
        server_key = base64.b64decode(i.split("|")[1]).decode("utf-8")
        if server_url in server_names:
            result.append('<table style="border:2px solid black;">'+ '<tr>' + '<th>' + server_url + '</th>' + '<th>' + '<textarea readonly style="border:double 2px green;" id="print_key" name="key" rows="10" cols="50">' + server_key + '</textarea>' + '</th>' + '</tr>' + '</table>')

    return "<br>".join(result)

def checkSign(signature, threshold=2):
    # cycle through the signature list
    global server_names
    signatureList = json.loads(signature)
    for i in signatureList:
        base64_key = (i.split("|")[1])
        encrypted_message = encrypt_message(base64_key, SECRET)
        server_url = base64.b64decode(i.split("|")[0]).decode("utf-8")
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
            print(f"Error, server {server_url} is not working")
            if(server_url in server_names):
                server_names.remove(server_url)
    print(f"Server signed: {(server_names)}")

    if(len(server_names) >= threshold):
        print("Total servers: ", len(server_names))
        return True
    return False

@app.route("/loginpassword", methods=["GET", "POST"])
def login_password():
    if request.method == "POST":
            # Get the username and password values from the form
            username = request.form["username"]
            password = request.form["password"]

            r = identify(username, password)
            if r.status_code == 200:
                print("Token: ", r.json()['token'])
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

@app.route("/loginface", methods=["GET", "POST"])
def login_face():
    if request.method == "POST":
            # Get the username and password values from the form
            photo = request.form["photo"]

            r = identify_photo(photo)
            if r.status_code == 200:
                print("Token: ", r.json()['token'])
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
    global server_names
    server_names.clear()
    logout_user()
    return "User logged out"

@app.route("/")
@login_required
def index():
    return "Home page"

if __name__ == "__main__":
    app.run()

@app.route("/login")
def login():
    return """<head>
    <script src="scripts/webcam.js"></script>
    <link rel="stylesheet" href="style/style.css">
</head>
<body>
    <div class="contentarea">
        <div class="camera">
          <video id="video">Video stream not available.</video>
          <button id="startbutton">Take photo</button>
        </div>
        <canvas id="canvas"> </canvas>
        <div class="output">
          <form method="POST" action="""f'{IDP_BASE_URL}/profile1' """>
            <input type="image" id="photo" alt="The screen capture will appear in this box.">
            <input type="submit" value="Login">
          </form>
          <!--<img id="photo" alt="The screen capture will appear in this box." /> -->
        </div>
        <!--<button id="sendPhoto" onclick="sendPhoto()"></button>-->
    </div>
      
</body>"""

@app.route("/scripts/webcam.js")
def getWebcamJS():
    return """(() => {
    // The width and height of the captured photo. We will set the
    // width to the value defined here, but the height will be
    // calculated based on the aspect ratio of the input stream.
  
    const width = 320; // We will scale the photo width to this
    let height = 0; // This will be computed based on the input stream
  
    // |streaming| indicates whether or not we're currently streaming
    // video from the camera. Obviously, we start at false.
  
    let streaming = false;
  
    // The various HTML elements we need to configure or control. These
    // will be set by the startup() function.
  
    let video = null;
    let canvas = null;
    let photo = null;
    let startbutton = null;
  
    function showViewLiveResultButton() {
      if (window.self !== window.top) {
        // Ensure that if our document is in a frame, we get the user
        // to first open it in its own tab or window. Otherwise, it
        // won't be able to request permission for camera access.
        document.querySelector(".contentarea").remove();
        const button = document.createElement("button");
        button.textContent = "View live result of the example code above";
        document.body.append(button);
        button.addEventListener("click", () => window.open(location.href));
        return true;
      }
      return false;
    }
  
    function startup() {
      if (showViewLiveResultButton()) {
        return;
      }
      video = document.getElementById("video");
      canvas = document.getElementById("canvas");
      photo = document.getElementById("photo");
      startbutton = document.getElementById("startbutton");
  
      navigator.mediaDevices
        .getUserMedia({ video: true, audio: false })
        .then((stream) => {
          video.srcObject = stream;
          video.play();
        })
        .catch((err) => {
          console.error(`An error occurred: ${err}`);
        });
  
      video.addEventListener(
        "canplay",
        (ev) => {
          if (!streaming) {
            height = video.videoHeight / (video.videoWidth / width);
  
            // Firefox currently has a bug where the height can't be read from
            // the video, so we will make assumptions if this happens.
  
            if (isNaN(height)) {
              height = width / (4 / 3);
            }
  
            video.setAttribute("width", width);
            video.setAttribute("height", height);
            canvas.setAttribute("width", width);
            canvas.setAttribute("height", height);
            streaming = true;
          }
        },
        false
      );
  
      startbutton.addEventListener(
        "click",
        (ev) => {
          takepicture();
          ev.preventDefault();
        },
        false
      );
  
      clearphoto();
    }
  
    // Fill the photo with an indication that none has been
    // captured.
  
    function clearphoto() {
      const context = canvas.getContext("2d");
      context.fillStyle = "#AAA";
      context.fillRect(0, 0, canvas.width, canvas.height);
  
      const data = canvas.toDataURL("image/png");
      photo.setAttribute("src", data);
    }
  
    // Capture a photo by fetching the current contents of the video
    // and drawing it into a canvas, then converting that to a PNG
    // format data URL. By drawing it on an offscreen canvas and then
    // drawing that to the screen, we can change its size and/or apply
    // other changes before drawing it.
  
    function takepicture() {
      const context = canvas.getContext("2d");
      if (width && height) {
        canvas.width = width;
        canvas.height = height;
        context.drawImage(video, 0, 0, width, height);
  
        const data = canvas.toDataURL("image/png");
        photo.setAttribute("src", data);
      } else {
        clearphoto();
      }
    }
  
    // Set up our event listener to run the startup process
    // once loading is complete.
    window.addEventListener("load", startup, false);
  })();

  function sendPhoto(){
    var request = new XMLHttpRequest();

    // Instantiating the request object
    request.open("POST", "192.168.0.1:3000/login", true);
    request.setRequestHeader('Content-Type','application/x-www-form-urlencoded; charset=UTF-8');

    request.onreadystatechange = function() {
      if(this.readyState === 4 && this.status === 200) {
          document.getElementById("result").innerHTML = this.responseText;

      }
    };

    request.send();


  }
  """

@app.route("/style/style.css")
def getStyleCSS():
    return """
    #video {
    border: 1px solid black;
    box-shadow: 2px 2px 3px black;
    width: 320px;
    height: 240px;
  }
  
  #photo {
    border: 1px solid black;
    box-shadow: 2px 2px 3px black;
    width: 320px;
    height: 240px;
  }
  
  #canvas {
    display: none;
  }
  
  .camera {
    width: 340px;
    display: inline-block;
  }
  
  .output {
    width: 340px;
    display: inline-block;
    vertical-align: top;
  }
  
  #startbutton {
    display: block;
    position: relative;
    margin-left: auto;
    margin-right: auto;
    bottom: 32px;
    background-color: rgba(0, 150, 0, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.7);
    box-shadow: 0px 0px 1px 2px rgba(0, 0, 0, 0.2);
    font-size: 14px;
    font-family: "Lucida Grande", "Arial", sans-serif;
    color: rgba(255, 255, 255, 1);
  }
  
  .contentarea {
    font-size: 16px;
    font-family: "Lucida Grande", "Arial", sans-serif;
    width: 760px;
  }
  
    """