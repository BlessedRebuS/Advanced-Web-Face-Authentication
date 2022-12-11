from flask import Flask, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.secret_key = 'asdasdasd'  # Change this!

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.name = "user" + str(id)
        self.password = self.name + "_secret"
    
    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)

# Create some users with ids 1 to 20
users = [User(id) for id in range(1, 21)]
print(users)

@login_manager.user_loader
def user_loader(user_id):
    if user_id not in range(1, 21):
        return
    
    user = User(user_id)
    return user

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get the username and password values from the form
        username = request.form["username"]
        password = request.form["password"]

        # Find the user with the given username
        user = [x for x in users if x.name == username][0]

        # Check if the password is correct
        if password == user.password:
            # Log the user in
            token = user.name + "_" + user.password

            # Log the user in with the custom token
            login_user(user, remember=token)

            return "User logged in"
        else:
            return "Incorrect username or password"
    
    # If the user is already logged in, redirect to the home page
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