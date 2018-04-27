const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define User Model
const userShema = new Schema({
  email: {
    type: String,
    unique: true,
    lowercase: true
  },
  password: String
});

// On Save Hook, encrypt the password.
// Before saving a model, run this function
userShema.pre('save', function(next){

  // get access to the user model
  const user = this;

  // generate a salt, then run callback. The generated salt
  // is the 'salt' parameter
  bcrypt.genSalt(10, (err, salt) => {
    if(err) { return next(err); }

    // hash (encrypt) password using the generated salt. The
    // encrypted password is the 'hash' parameter, and contains
    // the generated salt and the hash. So:
    // salt + plan text = salt + hashed text
    bcrypt.hash(user.password, salt, null, (err, hash) => {
      if(err) { return next(err); }

      // overwrite plain text password with the encrypted one
      user.password = hash;
      next();
    });
  });
});


//
userShema.methods.comparePassword = function(candidatePassword, callback){
  bcrypt.compare( candidatePassword, this.password, (err, isMatch) => {
    if( err ) { return callback(err); }

    callback( null, isMatch );
  });
};

// Create the Model Class
const ModelClass = mongoose.model('user', userShema);

// Export the Model
module.exports = ModelClass;
