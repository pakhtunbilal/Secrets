const express = require('express')
const bodyparser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose')
require('dotenv').config()
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
const MongoDBStore = require('connect-mongodb-session')(session);

const app = express();
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyparser.urlencoded({extended:true}))

const store = new MongoDBStore(
  {
    uri: process.env.MONGO_URI,
    databaseName: 'connect_mongodb_session_test',
    collection: 'mySessions'
  },
  function(error) {
    console.log(error)
  });

store.on('error', function(error) {
  console.log(error)
});

app.use(session({
  secret: 'menahibtaunga',
  saveUninitialized: true,
  resave: true,
  // using store session on MongoDB using express-session + connect
  store: store
}));


app.use(passport.initialize())
app.use(passport.session())


mongoose.connect(process.env.MONGO_URI)

const SecretSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String
});

const SubmitSchema = new mongoose.Schema({
  secret:String
})

SecretSchema.plugin(passportLocalMongoose)
SecretSchema.plugin(findOrCreate)

const SecretUser = mongoose.model('user',SecretSchema)

const SubmitModel = mongoose.model('secret',SubmitSchema)

passport.use(SecretUser.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
 
passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "https://salmon-abalone-kit.cyclic.app/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
async function (accessToken, refreshToken, profile, done) {
  try {
    console.log(profile);
    // Find or create user in your database
    let user = await SecretUser.findOne({ googleId: profile.id });
    if (!user) {
      // Create new user in database
      const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
      const newUser = new SecretUser({
        username: profile.displayName,
        googleId: profile.id
      });
      user = await newUser.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}
));

app.get('/',async(req,res)=>{
    res.render('home')
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
  );

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/login',(req,res)=>{
    res.render('login')
})
app.get('/register',async (req,res)=>{
    res.render('register')  
})
app.get('/secrets',async(req,res)=>{
    if(req.isAuthenticated()){
      let secrets = await SubmitModel.find({})
        res.render("secrets",{
          secret:secrets
        })
    }else{
        res.redirect("login")
    }
    
})

app.get('/submit',(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit")
}else{
    res.redirect("login")
}
})

app.post('/submit',async(req,res)=>{
  let SubmittedSecret = req.body.secret;
  let secret =  await SubmitModel.insertMany({secret:SubmittedSecret})
  res.redirect('/secrets')

})

app.get("/logout", (req, res, next) => {
	req.logout(function(err) {
		if (err) {
			return next(err);
		}
		res.redirect('/');
	});
});

app.post('/register',async(req,res)=>{

    try {
		const registerUser = await SecretUser.register(
                    {username: req.body.username}, req.body.password
                );
		if (registerUser) {
			passport.authenticate("local") (req, res, function() {
				res.redirect("/secrets");
			});
		} else {
			res.redirect("/register");
		}
	} catch (err) {
		res.send(err);
	}

})

app.post('/login',passport.authenticate('local', { failureRedirect: '/login' }),async(req,res)=>{
    let username = req.body.username;

    const user = new SecretUser({
		username: req.body.username,
		password: req.body.password
	});
 
	req.login(user, (err) => {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});
    

    
})

app.listen(3000)



// this is bcrypt salting method
// const bcrypt = require('bcrypt')
// const SaltR = 10;
// register
// let username = req.body.username;
// const hash = bcrypt.hashSync(req.body.password, SaltR)

// let result = new SecretUser({
//     email : username,
//     password : hash
// })
//  result = await result.save()
//  if(result){
//     res.render('secrets')
// }else{
//     console.log('error')
// }
// login
// SecretUser.findOne({email: username})
//     .then((foundUser)=>{
//         if(foundUser) {
//           // bcrypt
//           if(bcrypt.compareSync(req.body.password, foundUser.password)){
//           res.render("secrets");
//         }
//        }
//       })
//       .catch((err)=>{
//         console.log(err)
//       })


// this is md5 hashing
// const md5 = require('md5')
// strore password using md5(password)

// this is mongoose encryption method
// const encrypt = require('mongoose-encryption')
// SecretSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:["password"]})
