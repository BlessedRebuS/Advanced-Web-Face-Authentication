const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
var http = require('http');
var shasum = require('shasum')

// A map to store the users and their credentials
const users = new Map();
// add a map with 5 users
users.set('user1', { password: 'user1' , encoding: 'Wy0xLjExNzIyNDI1ZS0wMiAgMS4wNTE4NzUwNWUtMDEgIDMuOTE2MDU5MDZlLTAyIC00LjIzMTQzNTgxZS0wMgogLTcuMzQ0Mjk2NTdlLTAyICA3LjA1MzQwMTMyZS0wMiAtMy4zMTIwOTgyM2UtMDIgLTguMjA2MjkwMDFlLTAyCiAgMi4zNTM5MzEzN2UtMDEgLTcuNTQxNDY3MjVlLTAyICA5LjI5MDQ4Mjg1ZS0wMiAgMS4xMjUzODU3NmUtMDEKIC0yLjM3NzM3ODc5ZS0wMSAgMS42ODc5ODExOWUtMDMgIDIuNDU2MTkxMThlLTAyICA5LjI4MzgxNjgxZS0wMgogLTEuMjAyNDgxOTllLTAxIC0xLjM4NjkxODg3ZS0wMSAtNi45MDA4NDg0NWUtMDIgLTMuNDE3ODgzODFlLTAyCiAgMS40NzE1MTc2MWUtMDMgIDkuOTQzNTgyMTJlLTAyICAxLjM3NDQ3OTAxZS0wMiAgMS4wMjgzOTY0MWUtMDEKIC0xLjIwNjIzMTcxZS0wMSAtMy4zNzIyOTAxM2UtMDEgLTEuMjIyNjk3ODdlLTAxIC00LjE3NTcyMjk3ZS0wMgogIDcuOTAzMjA3MDllLTAyIC0xLjIyNjQ1NjE3ZS0wMSAtMS44NTk5MTA2MGUtMDIgIDcuOTE0NDI0NjllLTAyCiAtMS4yNDgyMzg2OGUtMDEgLTIuNjkwODEyMjBlLTAyICA3LjUwNzIxNDcwZS0wMiAgOC45ODgyNTM3N2UtMDIKICA0LjI2Mjc5MDA4ZS0wMyAtNS40NTgxODQzM2UtMDIgIDIuMDk5NDI1NDllLTAxICAxLjUxMjE4OTgxZS0wMQogLTEuNjM1NDM3NjFlLTAxICA5LjkzMTY3NzU4ZS0wMiAtMi4xMTUxNDYwN2UtMDIgIDMuMDUwODYxNjZlLTAxCiAgMi4wMjM4ODE2N2UtMDEgIDUuNDA5MTU4NzdlLTAzICA1LjcyOTE5MzI0ZS0wMiAtMS40OTQ4NzI3MmUtMDEKICAxLjA5MTU0ODczZS0wMSAtMi43MjU0ODY0NmUtMDEgIDcuODcwODMwNjBlLTAyICAxLjg2NjgzODQ5ZS0wMQogIDIuNDYxMDI3MTdlLTAyICA2LjI5MTMzNzMxZS0wMiAgNS41ODc4NjU0MWUtMDIgLTEuNDQ5NjI4MDNlLTAxCiAtMS41NDM2MTQyN2UtMDIgIDguNDIyMTIyOTBlLTAyIC0yLjA5NDg3NjE3ZS0wMSAgMS40ODYwNzk5OWUtMDEKICA5LjA3MTM5MTgyZS0wMiAtNy45ODUwNTc2OGUtMDIgLTQuMzI2OTY0MTdlLTAyIC0xLjk4OTE3OTg1ZS0wMgogIDkuMDg2ODU3NzRlLTAyICAxLjA5NTEzMTc4ZS0wMSAtMS4yMDQyMzY4OWUtMDEgLTEuNTM3ODgwMTVlLTAxCiAgNS42OTI4NTQxNWUtMDIgLTIuNDM1OTM3NTJlLTAxIC03LjU2ODUyMTgwZS0wMiAgNi41Mjg4OTk4MmUtMDIKIC05Ljg3NTc4NzA1ZS0wMiAtMS40NTUzNDI5MmUtMDEgLTIuNjgxMTA3MjJlLTAxICA2LjEyMjYxMTQ2ZS0wMgogIDQuNzIwNTE4NTllLTAxICAyLjIxNzA2MTIyZS0wMSAtMi4wNTEwMjYwOGUtMDEgIDcuOTY1NzAyNTZlLTAzCiAtNi44ODQyNjc5M2UtMDIgLTIuNTc5MzQyMjBlLTAyICA5LjU4NTUwMjc0ZS0wMiAgMS4wNzA1NTQ5M2UtMDEKIC0xLjI2MDAyNDAxZS0wMSAtNC43NDEzNTcyN2UtMDIgLTIuMTA1NTY0ODFlLTAyICAxLjA0MDExNDMxZS0wMQogIDIuMTgyMDcwMDJlLTAxICAxLjE3NjE3NzExZS0wMSAtMy4zMjMyOTMxMGUtMDIgIDIuNjUzMDA1NzJlLTAxCiAgNC44NDEyMzgyNmUtMDIgIDEuMTQzNTIwOTJlLTAxICA1LjQxNDAzOTY0ZS0wMiAgOS44ODgwNjQxMmUtMDIKIC02LjYwNjYxOTA2ZS0wMiAtOC41Njc1NTIyN2UtMDIgLTEuNTgyMjQ1ODNlLTAxIC01LjMzNjcwNjM0ZS0wMgogLTEuNDY4MzgyNzhlLTAyIC00Ljk2NjY4MjIwZS0wMiAgNy40NDk2NDMzMWUtMDIgIDEuNDI1MDE2MjJlLTAxCiAtMi4xMjUxMTQzNWUtMDEgIDIuMTU2MDE5OTZlLTAxIC01LjcyMjA0NTkwZS0wNiAtNy44NzczNjQwMWUtMDIKICA2LjgxNTE1MDM4ZS0wMiAgOC45OTgwNDY4MmUtMDIgLTEuNTU2Nzc1NzJlLTAxIC0xLjkyMjE0ODQ3ZS0wMgogIDIuMTQxNTc2NTZlLTAxIC0yLjQ1NjA1NDY5ZS0wMSAgMS42Mjg0MDE0M2UtMDEgIDIuMDQzNjQ2ODdlLTAxCiAgMy43ODM3NTUwMGUtMDIgIDcuNTkxNjE3MTFlLTAyICA2Ljg3MDA3OTc5ZS0wMiAgMS4wMTc3MDI4OWUtMDEKIC0yLjgyMTM3OTkwZS0wMiAtNC44MDA0MzI5MmUtMDIgLTcuNzUzMTU5MTFlLTAyIC00LjcyMTM1MDIyZS0wMgogIDIuNDk5NjMxMDVlLTAyIC0zLjE3OTYzMjg3ZS0wMiAgNi40Njk0NTgzNGUtMDIgLTQuMjYwMjE1OTFlLTAyXQ===='});
users.set('user2', { password: '' , encoding: 'Wy0wLjA3NTY5MzE4ICAwLjA2MTI4MDMzIC0wLjAwMDQ0MTkzIC0wLjA1ODA4MjYxICAwLjAwMTAxMTk3IC0wLjEwNjU1Mzk2CiAgMC4wMDM5NjAyOCAtMC4xMTE0NDM3MyAgMC4yMTY4MTg5OSAtMC4wNzkxNDAxOSAgMC4xMjc5MTIzMyAtMC4wNDM3Mjk1NAogLTAuMjM2NDQzMzEgIDAuMDA0NTQ5MTMgLTAuMDc3NjE4NTggIDAuMDM5NzA1OTMgLTAuMTcyOTU1NTQgLTAuMDc3NjAwMDgKIC0wLjAyNzU1ODE2IC0wLjA4Mjc1MTU1ICAwLjA5ODcwMzE1ICAwLjAwNzYzNjU3ICAwLjA1NDk1MjAzICAwLjE2MDAyOTA1CiAtMC4xNjUxNTE1OCAtMC4yMDMzMTA1OCAtMC4xNjQwMTg0NSAtMC4xNTkyMjE5NSAgMC4wMjg2NTI0OCAtMC4xMTg1NTM1MwogLTAuMDExNTY3MjYgIDAuMDg5NTY0NTUgLTAuMTM0MjI5NjMgLTAuMDk0Mzc5ODkgLTAuMDA4NDM0NSAgIDAuMDIxMDU0OTkKIC0wLjAyOTk1MDk1IC0wLjAzODY2Mzc0ICAwLjE5ODUzNjQ0IC0wLjAwNTgwMzEzIC0wLjExNzQxOTYyICAwLjAwNjQxNzM1CiAgMC4wMjc4NTczNCAgMC4yOTEwODQyOSAgMC4xNzA3NzM3ICAgMC4xMTE0MjUwMyAtMC4wMjAyNDk1NCAtMC4wNzkzNzczMQogIDAuMDg3NjQ5MDMgLTAuMjY2NTMzNjEgIDAuMDg0NDMyMjcgIDAuMTYzNTMzODEgIDAuMDIzMzg4MDYgIDAuMDg0ODg4MTgKICAwLjA2MTk2ODA1IC0wLjIxNzk4OTMzICAwLjA0OTMzMzEzICAwLjA5MTYzNTU4IC0wLjIwODY1OTQ0ICAwLjE2Nzc3NDYyCiAgMC4wNDczMDYzNyAtMC4wNDkwODQ4NCAgMC4wNTY4NzE3MiAgMC4wNDM4Mzc5OCAgMC4xMzQwOTUzICAgMC4xMDE0NzU4CiAtMC4xMzA3MjI2NCAtMC4wNjk0MTUyMyAgMC4xMTIwODU5NSAtMC4yODEyNTUxOSAtMC4wMTEzMTkzNSAgMC4xMTM4ODA1NgogLTAuMDk2NzY5OSAgLTAuMjQyMDU3OCAgLTAuMjM4NTY3NjUgIDAuMDI0MDcwMDQgIDAuNDAyNzYyODkgIDAuMjI0MjM1MDYKIC0wLjA3MDA4NzkyICAwLjAyOTA0MDIgIC0wLjA4MTk1ODg4IC0wLjA1MzU5NDk0ICAwLjA5NzY3NDkxICAwLjA0OTY2MjYzCiAtMC4xNTAwODM4OCAtMC4wMTQ1ODIwMSAtMC4wOTMxNTExNSAgMC4wNDYxMjcwOCAgMC4xODQ4ODM1MiAgMC4wNTU0OTU3NwogLTAuMDg2NDA5NzEgIDAuMjc0NTE0MTQgLTAuMDA3NzgwMzMgIDAuMDQwOTIxMDQgIDAuMDM2MTY5NTUgIDAuMDU3MjMwMgogLTAuMTEwMzU4MDUgLTAuMDExOTE0MTMgLTAuMTMwODY5NzUgIDAuMDQ0NDc3NTIgIDAuMDIxMjg5NjkgLTAuMDk5MjcwNgogLTAuMDQxMjE1MzggIDAuMTEzNzc1MzUgLTAuMTU4MzMxMTcgIDAuMTIxODE4OTggLTAuMDA2Njg2NDggLTAuMDY5NTUwMzIKIC0wLjExMTQxMTgxICAwLjA0Njg2MzM2IC0wLjIxNzQxNDQ3ICAwLjAwMTI2ODk0ICAwLjE5MzUyNTk0IC0wLjI0MDE0NDk3CiAgMC4xNzg4NzA3NSAgMC4yMDU0NTQzICAgMC4xMDEwMDUwNCAgMC4xMjg1MzY5NSAgMC4wNjY2NDY4ICAgMC4wMTc5MjA5NwogIDAuMDM3NTY1NzYgLTAuMDY2MTE1NTQgLTAuMTE4MDY4MjYgLTAuMDQ0NjgyMzIgIDAuMTAxODM0MDEgLTAuMDM4MzI0NwogIDAuMTAwOTg3MTUgLTAuMDAyNzc0MDdd===='});
users.set('user3', { password: 'user3'});
users.set('user4', { password: 'user4'});
users.set('user5', { password: 'user5'});

// A helper function to check if the given credentials are correct
const checkCredentials = (username, password, encoding) => {
  if (!users.has(username)) {
    return false;
  }
  if (encoding != null) {
    // has to be validated from the trust servers
    console.log("User " + username + " is partially authenticated");
    return true;
  }

  const user = users.get(username);

  //console.log(user, user.password, user.encoding)
  if (user.password === password){
    console.log("User " + username + " is authenticated");
    return true;
  }
  return false
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
  const { username } = req.headers;
  const { encoding } = req.headers;
  const { threshold } = req.headers;
  const user = users.get(username);

  callback = function(response) {
    signature = '';
    response.on('data', function (chunk) {
      // console.log("Chunk: " + chunk)
      signature += chunk;
    });
    response.on('end', function () {
      // based on threshold, check if the signature are enough
      var count = (signature.match(/ERR/g) || []).length;
      console.log("Count: " + count + " for signature: " + signature)
      if(count > threshold) {
        res.status(401).send({
          message: 'Unauthorized: Invalid credentials'
        });
        return;
      }

      const jwt_user = {
        username: username,
        encoding_shasum: shasum(user.encoding),
      }
      jwt.sign({user:jwt_user}, 'secretkey',(err,token)=>{
            res.json({
                token, 
                signature,
            });
      });
    });
  }
  if(encoding != null) {
  //console.log("Encoding: " + encoding, "Saved Encoding: " + user.encoding)
  var options = {
    host: '127.0.0.1',
    path: '/',
    port: '1234',
    headers: {
      'Content-Type': 'application/json',
      'username': username,
      'saved_encoding': user.encoding,
      'received_encoding': encoding
    }
  };
  } else {
    var options = {
      host: '127.0.0.1',
      path: '/',
      port: '1234',
      headers: {
        'username': username,
        'Content-Type': 'application/json'
      }
    };
  }
  // request to the trust controller
  var req2 = http.request(options, callback);
  req2.end();

});

app.listen(3000, () => {
  console.log('Identity provider listening on port 3000!');
});
