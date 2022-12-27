const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
var http = require('http');

var options = {
  host: '127.0.0.1',
  path: '/',
  port: '1234',
  headers: {
    'Content-Type': 'application/json',
  }
};

// A map to store the users and their credentials
const users = new Map();
// add a map with 5 users
users.set('user1', { password: 'user1' });
users.set('user2', { password: 'user2' });
users.set('user3', { password: 'user3' });
users.set('user4', { password: 'user4' });
users.set('user5', { password: 'user5' });

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

// a route to get only the signature
app.get('/signature', (req, res) => {

  callback = function(response) {
    signature = '';
    response.on('data', function (chunk) {
      signature += chunk;
    });
    
    response.on('end', function () {
    console.log("Signature Request");
            res.json({
                signature,
            });

    });
  }

  // request to the trust controller
  var req2 = http.request(options, callback);
  req2.end();

});


// A route to get the current user's profile
app.get('/profile', checkAuthenticated, (req, res) => {

  callback = function(response) {
    signature = '';
    response.on('data', function (chunk) {
      signature += chunk;
    });
    
    response.on('end', function () {
      const { username } = req.headers;
      const user = users.get(username);
      console.log("User " + username + " is authenticated");
      jwt.sign({user:user},'secretkey',(err,token)=>{
            res.json({
                token, 
                signature,
            });
      });
    });
  }

  // request to the trust controller
  var req2 = http.request(options, callback);
  req2.end();

});


app.listen(3000, () => {
  console.log('Identity provider listening on port 3000!');
});
