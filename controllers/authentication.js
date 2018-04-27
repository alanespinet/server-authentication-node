const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser( user ){
  const timestamp = new Date().getTime();
  return jwt.encode({
    sub: user.id,
    iat: timestamp
  }, config.secret);
}


exports.signin = (req, res, next) => {
  // user already has had his email and password authorizied,
  // just give him a token.
  // 'req.user' comes from the call to 'done(null, user)' in passport
  res.send({ token: tokenForUser(req.user) });
};



exports.signup = (req, res, next) => {

  const email = req.body.email;
  const password = req.body.password;

  if( !email || !password ){
    return res.status(422).send({ error: 'You must provide email and password' });
  }

  // See if a User with the given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if( err ) { return next(err); }

    // If exists, return and Error
    if( existingUser ) {
      return res.status(422).send({ error: 'Email is in use' });
    }

    // If does NOT exist, create User
    const user = new User({
      email: email,
      password: password
    });

    user.save( err => {
      if( err ) { return next(err); }

      // Respond to Request indicating User created
      res.json({ token: tokenForUser( user ) });
    });

  });

};
