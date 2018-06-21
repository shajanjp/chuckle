const config = require('../../../config/env/');
const User = require('mongoose').model('user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

exports.userbyId = (req, res, next, userId) => {
  User.findOne({_id: userId})
  .then((userFound) => {
    res.locals.userId = userFound._id;
    next();
  })
  .catch((err) => {
    return res.status(404).json({
      'message': 'User not found!',
      'errors': err,
    });
  });
};

// middleware to check authorization
exports.isAuthorized = function(req, res, next) {
  let accessToken = req.headers['authorization'];
  if (!accessToken || (accessToken.split(' '))[0] !== 'Bearer') {
    return res.status(401).json({
      'error': 'Invalid token!',
    });
  }

  jwt.verify(accessToken.split(' ')[1], config.jwt.secret_key, function(err, decoded) {
    if (err) {
return res.status(401).json({
        'error': 'Invalid token!',
      });
} else if (decoded) {
      res.locals.authUserId = decoded.userId;
      res.locals.authUserRole = decoded.userRole;
      next();
    } else {
return res.status(500).json({
        'error': 'Something went wrong with token !',
      });
}
  });
};

// signs up new user and responds with token
exports.signUpUser = (req, res) => {
  let userDetails;
  User.findOne({email: res.locals.user.email})
  .then((userFound) => {
    if (userFound && userFound.email) {
      return Promise.reject({
        message: 'User already exists !',
      });
    } else {
return bcrypt.hash(res.locals.user.password, saltRounds);
}
  })
  .then((hash) => {
    let newUser = new User({
      firstName: res.locals.user.firstName,
      lastName: res.locals.user.lastName,
      role: res.locals.user.role,
      username: res.locals.user.username,
      email: res.locals.user.email,
      password: hash,
    });
    userDetails = newUser;
    return newUser.save();
  })
  .then((userSaved) => {
    return jwt.sign({
      'userId': userDetails._id,
      'userRole': userDetails.role,
    }, config.jwt.secret_key, {expiresIn: config.jwt.expiry});
  })
  .then((jwtCreated) => {
    let resUserDetails = userDetails;
    resUserDetails.password = undefined;
    resUserDetails.token = jwtCreated;
    res.json( {
      'user': resUserDetails,
      'token': jwtCreated,
    });
  })
  .catch((err) => {
    return res.status(400).json({
      'message': err.message || 'Internal error',
    });
  });
};

// signs in user using username and password, responds with JWT
exports.signInUser = (req, res) => {
  let userDetails;
  User.findOne({email: res.locals.user.email})
  .exec()
  .then((userFound) => {
    if (userFound && userFound.email) {
      userDetails = userFound;
      return bcrypt.compare(res.locals.user.password, userFound.password);
    } else {
      return Promise.reject('Username password missmatch!');
    }
  })
  .then((passwordMatch) => {
    if (passwordMatch === true) {
      return jwt.sign({
        'userId': userDetails._id,
        'userRole': userDetails.role,
      }, config.jwt.secret_key, {expiresIn: config.jwt.expiry});
    } else {
      return Promise.reject('Username password missmatch!');
    }
  })
  .then((jwtCreated) => {
    userDetails.password = undefined;
    res.json({
      'user': userDetails,
      'token': jwtCreated,
    });
  })
  .catch((err) => {
    res.status(400).json({
      'status': 0,
      'error': err,
    });
  });
};

exports.getUsers = (req, res) => {
  User.find({})
  .then((userList) => {
    return res.status(200).json(userList);
  })
  .catch((err) => {
    return res.status(500).json({
      'message': 'Internal error',
      'errors': err,
    });
  });
};

exports.updateUser = (req, res) => {
  User.update({_id: res.locals.userId}, res.locals.user, {safe: true})
  .then((userUpdated) => {
    return res.status(200).json({});
  })
  .catch((err) => {
    return res.status(500).json({
      'message': 'Internal error',
      'errors': err,
    });
  });
};

exports.getUser = (req, res) => {
  User.findOne({_id: res.locals.userId}).exec()
  .then((userFound) => {
    return res.status(200).json(userFound);
  })
  .catch((err) => {
    return res.status(500).json({
      'message': 'Internal error',
      'errors': err,
    });
  });
};

exports.removeUser = (req, res) => {
  User.remove({_id: res.locals.userId})
  .then((userRemoved) => {
    return res.status(200).json({});
  })
  .catch((err) => {
    return res.satus(500).json({
      'message': 'Internal error',
      'errors': err,
    });
  });
};

// responds with expired JWT
exports.signOutUser = (req, res) => {
  res.json({
    'status': 1,
    'success': 'User signout success',
    'token': jwt.sign({}, config.jwt.secret_key, {expiresIn: '0s'}),
  });
};

