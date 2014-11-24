var mongoose             = require('mongoose');
var passport             = require('passport');
var LocalStrategy        = require('passport-local').Strategy;
var TwitterStrategy      = require('passport-twitter').Strategy;
var FacebookStrategy     = require('passport-facebook').Strategy;
var GoogleStrategy       = require('passport-google-oauth').OAuth2Strategy;
var User                 = require('../models/user');
var authConfig           = require('../config/auth');


module.exports = function(passport) {
  var localStrategySettings = {
    passReqToCallback: true
  };

  var facebookStrategySettings = {
    clientID: authConfig.facebookAuth.clientID,
    clientSecret: authConfig.facebookAuth.clientSecret,
    callbackURL: authConfig.facebookAuth.callbackUrl,
    passReqToCallback: true
  };

  var facebookStuff = {

  }

  var twitterStrategySettings = {
    consumerKey: authConfig.twitterAuth.consumerKey,
    consumerSecret: authConfig.twitterAuth.consumerSecret,
    callbackURL: authConfig.twitterAuth.callbackURL,
    passReqToCallback: true
  };
  var googleStrategySettings = {
    clientID: authConfig.googleAuth.clientID,
    clientSecret: authConfig.googleAuth.clientSecret,
    callbackURL: authConfig.googleAuth.callbackURL,
    passReqToCallback: true
  };


  /**
   * Local Strategy setup
   */
  passport.use('signup', new LocalStrategy(localStrategySettings, function(req, username, password, done) {
      process.nextTick(function() {
        if(!req.user) {
          User.findOne({ username: username }, function(err, user) {
            if (err) {
              return done(err);
            }

            if (user) {
              return done(null, false, {message: 'User exists'});
            } else {
              var newUser = new User();
              newUser.local.username = username;
              newUser.local.password = newUser.generateHash(password);
              newUser.save(function(err) {
                if (err) throw err;
                return done(null, newUser);
              });
            }
          });
        } else {
          var user = req.user;
          user.local = {
            username: req.body.username,
            password: user.generateHash(req.body.password)
          };

          user.save(function(err) {
            if (err) throw err;
            return done(null, user);
          });
        }
      });

    }

  ));


  // Local Signin
  passport.use(new LocalStrategy(function(username, password, done) {
    User.findOne({ 'local.username': username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      } else {
        user.validPassword(password, function(err, isMatch) {
          return isMatch ? done(null, user) : done(null, false, { message: 'Incorrect password '});
        });
      }
    })
  }));


  /**
   * Facebook Strategy setup
   */
  passport.use(new FacebookStrategy(facebookStrategySettings, function(req, token, refreshToken, profile, done) {

    process.nextTick(function() {
      // Check if an user is already authenticated
      if(!req.user) {
        User.findOne({ 'facebook.id': profile.id }, function(err, user) {

          if (err) return done(err);

          if (user) {
            return done(null, user);
          } else {

            var newUser = new User({
              facebook: {
                id: profile.id,
                token: token,
                name: profile.name.givenName + ' ' + profile.name.familyName,
                email: profile.emails[0].value
              }
            });

            newUser.save(function(err) {
              if (err) throw err;
              return done(null, newUser);
            });
          }
        });
      } else {
        var user = req.user;
        user.facebook = {
          id: profile.id,
          token: token,
          name: profile.name.givenName + ' ' + profile.name.familyName,
          email: profile.emails[0].value
        };


        user.save(function(err) {
          if (err) throw err;
          return done(null, user);
        });
      }
    });

  }));


  /**
   * Twitter Strategy setup
   */
  passport.use(new TwitterStrategy(twitterStrategySettings, function(req, token, tokenSecret, profile, done) {

    process.nextTick(function() {

      if(!req.user) {
        User.findOne({ 'twitter.id' : profile.id }, function(err, user) {
          if (err) return done(err);

          if (user) {
            return done(null, user);
          } else {

            var newUser = new User({
              twitter: {
                id: profile.id,
                token: token,
                username: profile.username,
                displayName: profile.displayName
              }
            });

            newUser.save(function(err) {
              if (err) throw err;
              return done(null, newUser);
            });
          }
        });
      } else {
        var user = req.user;
        user.twitter = {
          id: profile.id,
          token: token,
          username: profile.username,
          displayName: profile.displayName
        };

        user.save(function(err) {
          if (err) throw err;
          return done(null, user);
        });
      }
    });

  }));


  /**
   * Google Strategy setup
   */
  passport.use(new GoogleStrategy(googleStrategySettings, function(req, token, refreshToken, profile, done) {
    process.nextTick(function() {
      if (!req.user) {
        User.findOne({'google.id': profile.id}, function(err, user) {
          if (err) return done(err);

          if (user) {
            return done(null, user);
          } else {

            var newUser = new User({
              google: {
                id: profile.id, token: token, name: profile.displayName, email: profile.emails[0].value
              }
            });

            newUser.save(function(err) {
              if (err) throw err;
              return done(null, newUser);
            });
          }
        });
      } else {
        var user = req.user;
        user.google = {
          id: profile.id,
          token: token,
          name: profile.displayName,
          email: profile.emails[0].value
        };

        user.save(function(err) {
          if (err) throw err;
          return done(null, user);
        });
      }
    });
  }));


  /**
   * Serializing / Deserializing user
   */
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    })
  });
};

