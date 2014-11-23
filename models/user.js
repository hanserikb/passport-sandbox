var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;
var bcrypt = require('bcrypt');
var userSchema = new Schema({
  local: {
    id: ObjectId,
    username: String,
    password: String
  },
  facebook: {
    id: String,
    token: String,
    email: String,
    name: String
  },
  twitter: {
    id: String,
    token: String,
    username: String,
    displayName: String
  },
  google: {
    id: String,
    token: String,
    name: String,
    email: String
  }
});

userSchema.methods.generateHash = function(password, cb) {
  var salt = bcrypt.genSaltSync(10);
  console.log('salted')
  return bcrypt.hashSync(password, salt);
};

userSchema.methods.validPassword = function(password, cb) {
  bcrypt.compare(password, this.local.password, function(err, isMatch) {
    return cb(err, isMatch);
  });
};

var User = mongoose.model('User', userSchema);

module.exports = User;
