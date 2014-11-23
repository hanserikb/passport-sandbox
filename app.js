var express              = require('express');
var expressHandlebars    = require('express-handlebars');
var bodyParser           = require('body-parser');
var session              = require('express-session');
var csrf                 = require('csurf');
var mongoose             = require('mongoose');
var passport             = require('passport');
var LocalStrategy        = require('passport-local').Strategy;
var flash                = require('connect-flash');
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
      User.findOne({ username: username }, function(err, user) {
        if (err) {
          return done(err);
        }

        if (user) {
          return done(null, false, req.flash('message', 'User exists'));
        } else {
          var newUser = new User({username: req.body.username, password: req.body.password});
          newUser.save(function(err) {
            if (err) throw err;
            return done(null, newUser);
          })
        }
      });
    });
  }

));


// Set user information in the user cookie, if possible
passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
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

passport.serializeUser(function(user, done) {
  console.log(user)
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  console.log(id)
  User.findOne({_id: id }, function(err, user) {
    console.log('found', user)
    done(err, user);
  })
});

app.use(passport.initialize());
app.use(passport.session());


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
