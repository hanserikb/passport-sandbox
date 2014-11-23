var express              = require('express');
var expressHandlebars    = require('express-handlebars');
var bodyParser           = require('body-parser');
var session              = require('express-session');
var csrf                 = require('csurf');
var mongoose             = require('mongoose');
var passport             = require('passport');
var LocalStrategy        = require('passport-local').Strategy;
var TwitterStrategy      = require('passport-twitter').Strategy;
var FacebookStrategy     = require('passport-facebook').Strategy;
var GoogleStrategy       = require('passport-google-oauth').OAuth2Strategy;
var flash                = require('connect-flash');
var authConfig           = require('./config/auth');
var app                  = express();


mongoose.connect('mongodb://localhost');

var User = require('./models/user');

// Setup session
app.use(session({
  name: 'sid',
  secret: '1o9zvitwZrevXfax0H5eC3wTydWHG4eD27CRP6BQ',
  cookie: {
    maxAge: 3600000 // 24h
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));

// Setup and use handlebars as a view rendering engine
app.engine('handlebars', expressHandlebars({
  defaultLayout: 'base'
}));
app.set('view engine', 'handlebars');
app.set('views', __dirname + '/views');
app.use(flash());
// Add cross site resource forgery protection
app.use(csrf());
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // handle CSRF token errors here
  res.status(403);
  res.send('session has expired or form tampered with')
});



passport.use('signup', new LocalStrategy({
    passReqToCallback: true
  }, function(req, username, password, done) {
    process.nextTick(function() {
      console.log('the user', req.user)
      if(!req.user) {
        User.findOne({ username: username }, function(err, user) {
          if (err) {
            return done(err);
          }

          if (user) {
            return done(null, false, req.flash('message', 'User exists'));
          } else {
            var newUser = new User();
            newUser.local.username = username;
            newUser.local.password = newUser.generateHash(password);
            newUser.save(function(err) {
              console.log('done saveing')
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


// Set user information in the user cookie, if possible
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

passport.use(new FacebookStrategy({
  clientID: authConfig.facebookAuth.clientID,
  clientSecret: authConfig.facebookAuth.clientSecret,
  callbackURL: authConfig.facebookAuth.callbackUrl,
  passReqToCallback: true
}, function(req, token, refreshToken, profile, done) {

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

passport.use(new TwitterStrategy({
  consumerKey: authConfig.twitterAuth.consumerKey,
  consumerSecret: authConfig.twitterAuth.consumerSecret,
  callbackURL: authConfig.twitterAuth.callbackURL,
  passReqToCallback: true
}, function(req, token, tokenSecret, profile, done) {

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

passport.use(new GoogleStrategy({
  clientID: authConfig.googleAuth.clientID,
  clientSecret: authConfig.googleAuth.clientSecret,
  callbackURL: authConfig.googleAuth.callbackURL,
  passReqToCallback: true
}, function(req, token, refreshToken, profile, done) {
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


app.use(passport.initialize());
app.use(passport.session());




app.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', {
  successRedirect: '/dashboard',
  failureRedirect: '/login'
}));

app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('/auth/twitter/callback', passport.authenticate('twitter', {
  successRedirect: '/dashboard',
  failureRedirect: '/login'
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email']}));
app.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/dashboard',
  failureRedirect: '/login'
}));

app.get('/connect/local', function(req, res) {
  res.render('connect-local', { message: req.flash('loginMessage'), csrfToken: req.csrfToken()});
});
app.post('/connect/local', passport.authenticate('signup', {
  successRedirect: '/dashboard',
  failureRedirect: '/connect/local',
  failureFlash: true
}));

app.get('/connect/twitter', passport.authorize('twitter', { scope: 'email' }));
app.get('/connect/twitter', passport.authorize('twitter-signup', {
  successRedirect: '/dashboard',
  failureRedirect: '/connect/twitter',
  failureFlash: true
}));

app.get('/connect/google', passport.authorize('google', { scope: ['profile', 'email']}));
app.get('/connect/google', passport.authorize('google-signup', {
  successRedirect: '/dashboard',
  failureRedirect: '/connect/google',
  failureFlash: true
}));

app.get('/connect/facebook', passport.authorize('facebook', { scope: 'email' }));
app.get('/connect/facebook', passport.authorize('facebook', {
  successRedirect: '/dashboard',
  failureRedirect: '/connect/facebook',
  failureFlash: true
}));

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/login');
});

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  })
});




// Set flash messages as local view variables and delete its session, preventing
// messages to appear on site refresh
app.use(function(req, res, next) {
  if(req.session && req.session.flash) {
    res.locals.flash = req.session.flash;
    delete req.session.flash;
  }
  next();
});

app.get('/', function(req, res) {
  res.render('index');
});

app.get('/login', function(req, res) {
  res.render('login', { csrfToken: req.csrfToken() });
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/register', function(req, res) {
  res.render('register', { csrfToken: req.csrfToken() });
});

app.post('/register', passport.authenticate('signup', {
  successRedirect: '/dashboard',
  failureRedirect: '/register',
  failureFlash: true
}));

app.get('/dashboard', isAuthenticated, function(req, res) {
  res.render('dashboard', {
    user: req.user
  });
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.session.flash = 'Not authenticated'
    res.redirect('/login');
  }
}

app.use(function(req, res, next) {
  console.log(res.locals)
  next();
});

app.listen(8000);
