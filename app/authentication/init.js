const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;

const authenticationMiddleware = require('./middleware');

//Password Generation
const saltRounds = 10;
const password = 'dev';
const salt = bcrypt.genSaltSync(saltRounds);
const passwordHash = bcrypt.hashSync(password, salt);

const user = {
    username: 'dev',
    passwordHash,
    id: 1
};

function findUser(username, callback) {
    if(username === user.username) {
        return callback(null, user);
    }

    return callback(null);
}

passport.serializeUser( function(user, done) {
   done(null, user.username)
});

passport.deserializeUser( function(username, done) {
    findUser(username, done)
});

function initPassport() {
    passport.use(new LocalStrategy(
        function(username, password, done) {
            findUser(username, function (err, user) {
                if (err) {
                    return done(err)
                }
                //User not found
                if (!user) {
                    console.log("User wasn't found");
                    return done(null, false)
                }
                //Use hashed password
                bcrypt.compare(password, user.passwordHash, (err, isValid) => {
                    if (err) {
                        return done(err)
                    }
                    if (!isValid) {
                        return done(null, false)
                    }
                    return done(null, user)
                })
            })
        }
    ));

    passport.authenticationMiddleware =  authenticationMiddleware
}

module.exports = initPassport;