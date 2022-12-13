const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');

// A map to store the users and their credentials
const users = new Map();
// add a default user
users.set('asd', { password: 'asd' });

// A helper function to check if the given credentials are correct
const checkCredentials = (username, password) => {
  if (!users.has(username)) {
    return false;
  }

  const user = users.get(username);
  return user.password === password;
};

// A middleware to check if the user is authenticated
const checkAuthenticated = (req, res, next) => {
  const { username, password } = req.headers;
  if (checkCredentials(username, password)) {
    next();
  } else {
    res.status(401).send({
      message: 'Unauthorized: Invalid credentials'
    });
  }
};

// A route to register a new user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (users.has(username)) {
    res.status(400).send({
      message: 'Bad Request: A user with the given username already exists'
    });
  } else {
    users.set(username, { password });
    res.send({
      message: 'Successfully registered new user'
    });
  }
});

// A route to get the current user's profile
app.get('/profile', checkAuthenticated, (req, res) => {
  const { username } = req.headers;
  const sign = "SERVER1_SIGNED"
  const result = users.get(username) + sign;
  console.log("User " + username + " is authenticated");

  jwt.sign({result:result},'secretkey',(err,token)=>{
        res.json({
            token,
        });
  });

});

app.listen(3000, () => {
  console.log('Identity provider listening on port 3000!');
});
