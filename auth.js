const jwt = require('jsonwebtoken');


// Middleware for token validation
function tokenValidation(req, res, next) {
  try {
    if (req.headers.authorization != undefined) {
      jwt.verify(
        req.headers.authorization,
        process.env.JWT_SECRET_KEY,
        (err, decode) => {
          if (decode) {
            req.body.id = decode.user_id;
            req.body.role = decode.role;
            next();
          } else {
            res.send("invalid token");
          }
        }
      );
    } else {
      res.send("no token");
    }
  } catch (error) {
    console.log(error);
  }
}

// Middleware to check the role of the user
function roleCheck(role) {
  return function (req, res, next) {
    if ((req.body.role == role)) {
      next();
    } else {
      res.status(401).json({ message: "you are unauthorized" });
    }
  };
}

module.exports = {tokenValidation, roleCheck}