

module.exports = function(app, passport) {


  app.get('/register', function(req, res) {
    res.render('register', { csrfToken: req.csrfToken() });
  });

  app.post('/register', passport.authenticate('signup', {
    successRedirect: '/dashboard',
    failureRedirect: '/register',
    failureFlash: true
  }));

  app.get('/login', function(req, res) {
    res.render('login', { csrfToken: req.csrfToken() });
  });

  app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  }));

  app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/login');
  });

  // Secure dashboard area
  app.get('/dashboard', isAuthenticated, function(req, res) {
    res.render('dashboard', {
      user: req.user
    });
  });


  /**
   * Routes to authenticate user with social media
   */
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

  /**
   * Routes to connect social media authenticate to existing accounts
   */
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


  function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    } else {
      req.session.flash = 'Not authenticated'
      res.redirect('/login');
    }
  }
};
