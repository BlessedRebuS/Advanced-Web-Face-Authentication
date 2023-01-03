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
users.set('user1', { password: 'user1' , encoding: '1234567890'});
users.set('user2', { password: '' , encoding: '1234567890'});
users.set('user3', { password: 'user3'});
users.set('user4', { password: 'user4'});
users.set('user5', { password: 'user5'});

// A helper function to check if the given credentials are correct
const checkCredentials = (username, password, encoding) => {
  if (!users.has(username)) {
    return false;
  }

  const user = users.get(username);
  console.log(user, user.password, user.encoding)
  return (user.password === password || user.encoding === encoding);
};


// A middleware to check if the user is authenticated
const checkAuthenticated = (req, res, next) => {
  const { username, password, encoding } = req.headers;
  if (checkCredentials(username, password, encoding)) {
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
      // console.log("Chunk: " + chunk)
      signature += chunk;
    });
    
    response.on('end', function () {
      // console.log(req);
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
