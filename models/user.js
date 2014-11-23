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
  }
});

userSchema.methods.validPassword = function(password, cb) {
  bcrypt.compare(password, this.local.password, function(err, isMatch) {
    return cb(err, isMatch);
  });
};

userSchema.pre('save', function(next) {
  var user = this;
console.log('presaving')
  if(!user.isModified('local.password')) return next();

  bcrypt.genSalt(10, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.local.password, salt, function(err, hash) {
      if (err) return next(err);
      user.local.password = hash;
      next();
    })
  })
});


var User = mongoose.model('User', userSchema);

module.exports = User;
