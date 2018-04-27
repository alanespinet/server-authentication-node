const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');


// Create options for JWT Strategy
const localOptions = {
  usernameField: 'email'
};

// Create Local Strategy
const localLogin = new LocalStrategy( localOptions, (email, password, done) => {
  // First looks for the user's email
  User.findOne( { email: email }, (err, user) => {
    // if an error raises or the user is not found:
    if( err ) { return done( err, false ); }
    if( !user ) { return done( null, false ); }

    // if the user is found, compare passwords
    user.comparePassword( password, (err, isMatch) => {
      if( err ) { return done( err, false ); }
      if( !isMatch ) { return done( null, false ); }

      return done( null, user );
    });
  });
});

// Create options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJWT.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
    // payload: the encoded token created in tokenForUser. User id is 'sub'
    // done: callback to indicate wheter the authentication was a success

    // See if the user id in the payload exists in our database
    // If it exists, call 'done' with that user
    // If it does NOT exist, call 'done' without the user

    // signature for done: done(error, success_object)
    User.findById(payload.sub, (err, user) => {
      if( err ) { return done(err, false); }

      // user found
      if( user ){
        return done( null, user );
      } else {
        return done( null, false );
      }
    });
});

// Tell passport to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);
