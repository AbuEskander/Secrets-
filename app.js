//jshint esversion:6
import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import mongooseEncryption from 'mongoose-encryption';
import bcrypt from 'bcrypt';
import expressSession from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import passportGoogleOauth20,{Strategy} from 'passport-google-oauth20';
import findOrCreatePlugin from 'mongoose-findorcreate';

mongoose.connect('mongodb://127.0.0.1:27017/users');

const app = express();
const port = 3000;
const salting = 10;

app.use(express.static('public'));
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(expressSession({
    secret: process.env.SECRET,
    saveUninitialized: false,
    resave: false
}));
app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
    name: String,
    password: String,
    googleId: String
});
let secret = process.env.SECRET;
userSchema.plugin(mongooseEncryption, {
    secret: secret,
    encryptedFields: ["password"]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreatePlugin)
const Users = mongoose.model('Users', userSchema);

passport.use(Users.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
passport.use(new Strategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", 
  },
  function(accessToken, refreshToken, profile, cb) {
    Users.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/', (req, res) => {
    res.render('home.ejs');
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.get("/register", (req, res) => {
    res.render('register.ejs');
});
app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render('secrets.ejs');
    } else {
        res.redirect('/login');
    }
});
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
    });
    res.redirect("/");
});
app.get("/auth/google",passport.authenticate("google",{scope:["profile"]}));

app.post('/register', (req, res) => {
    Users.register({
        username: req.body.username
    }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/");
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect("/secrets");
            })
        }
    });

});
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.post("/login", async (req, res) => {
    const newUser = new Users({
        username: req.body.username,
        passwrod: req.body.password
    });
    req.login(newUser, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect("/secrets");
            });
        }
    })
});
app.listen(port, () => {
    console.log(`listening on ${port}`);
});