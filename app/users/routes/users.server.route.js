const express = require('express');
const router = express.Router(); // eslint-disable-line new-cap
const userController = require('../controllers/users.server.controller.js');
const userValidator = require('../libraries/users.server.validation.js');

router.route('/signup')
.post(userValidator.validateSignUpUser, userController.signUpUser);

router.route('/signin')
.post(userValidator.validateSignInUser, userController.signInUser);

router.route('/signout')
.get(userController.isAuthorized, userController.signOutUser);

router.route('/')
.get(userController.getUsers);

router.route('/:userId')
.put(userValidator.validateInsertUser, userController.updateUser)
.get(userController.getUser)
.delete(userController.removeUser);

router.param('userId', userController.userbyId);

module.exports = router;
