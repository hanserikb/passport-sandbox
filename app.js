var express              = require('express');
var expressHandlebars    = require('express-handlebars');
var bodyParser           = require('body-parser');
var session              = require('express-session');
var csrf                 = require('csurf');
var passport             = require('passport');
var app                  = express();
require('mongoose').connect(require('./config/database').databaseUrl);
require('./config/passport')(passport);

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

/**
 * Cross-site request forgery protection
 */
app.use(csrf());
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // handle CSRF token errors here
  req.session.flash = 'session has expired or form tampered with';
  res.redirect('/login');
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

// Root route
app.get('/', function(req, res) {
  res.render('index');
});


// Authentication routes
require('./routes/passport')(app, passport);

// Start server
app.listen(8000);
