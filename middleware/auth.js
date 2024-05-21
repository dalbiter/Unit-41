const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

// 41.1.10 Auth middleware
function authenticateJWT(req, res, next) {
  try {
    const payload = jwt.verify(req.body._token, SECRET_KEY)
    req.user = payload
    console.log("You have a valid token!")
    return next()
  } catch(e) {
    return next() //don't worry about the error just catch it and move on to the next thing
  }
};

function ensureLoggedIn(req, res, next) {
  if(!req.user) {
    const e =  new ExpressError("Unauthorized", 401)
    return next(e)
  } else {
    return next()
  }
};

function ensureAdmin(req, res, next) {
  if(!req.user || req.user.type !== "admin") {
    const e = new ExpressError("Must be admin to view this page", 401)
    return next(e)
  } else {
    return next()
  }
};

module.exports = { authenticateJWT, ensureLoggedIn, ensureAdmin };