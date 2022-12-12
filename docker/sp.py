from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import requests

app = Flask(__name__)
app.secret_key = 'asdasdasd'  # Change this!

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# The base URL of the identity provider
IDP_BASE_URL = 'http://10.11.0.3:3000'

    
class User(UserMixin):
    def __init__(self, id):
        self.id = id
    
    def __repr__(self):
        return f"User: {self.id}"

def identify(username, password):
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get the username and password values from the form
        username = request.form["username"]
        password = request.form["password"]

        r = identify(username, password)
        if r.status_code == 200:
            u = User(r.json())
            login_user(u)
            print(r.json())
            return "User logged in"

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
    app.run(port=5000, debug=True, host='10.11.0.2')