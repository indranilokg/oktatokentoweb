var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var session = require('express-session');
var passport = require('passport');
var { Strategy } = require('passport-openidconnect');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

require('dotenv').config();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'CanYouLookTheOtherWay',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use('oidc', new Strategy({
  issuer: process.env.issuer,
  authorizationURL: process.env.issuer + '/v1/authorize',
  tokenURL: process.env.issuer + '/v1/token',
  userInfoURL: process.env.issuer + '/v1/userinfo',
  clientID: process.env.clientId,
  clientSecret: process.env.clientSecret,
  callbackURL: process.env.redirect_uri,
  scope: 'openid profile'
}, (issuer, profile, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/signin', passport.authenticate('oidc'));
app.post('/signout', (req, res) => {
  req.logout(err => {
     if (err) { return next(err); }
     let params = {
        id_token_hint: '',
        post_signout_redirect_uri: 'http://localhost:3001/'
     }
     res.redirect('/');
     req.session.destroy();
  });
});

app.get('/ssosignin', (req, res) => {
  console.log(req.query.accessToken);
  passport.authenticate('oidc', { loginHint: req.query.accessToken })(req,res);
});

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureMessage: true, failWithError: true }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.use('/profile', (req, res) => {
  res.render('profile', { user: req.user, authenticated: req.isAuthenticated() });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
