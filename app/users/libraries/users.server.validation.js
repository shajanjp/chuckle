const joi = require('joi');
// const mongoId = joi.string().length(24);

const userInsertSchema = joi.object().keys({
  username: joi.string().allow('').optional(),
  email: joi.string().allow('').optional(),
  firstName: joi.string().allow('').optional(),
  lastName: joi.string().allow('').optional(),
  password: joi.string().allow('').optional(),
  role: joi.string().allow('').optional(),
  permissions: joi.array().items(joi.string().allow('').optional()).optional().default([]),
});

exports.validateInsertUser = function(req, res, next) {
  joi.validate(req.body, userInsertSchema, {'stripUnknown': true}, function(err, validated) {
    if (err) {
return res.status(500).json({
        'errors': err.details[0].message,
      });
} else {
      res.locals.user = validated;
      return next();
    }
  });
};

exports.validateSignUpUser = function(req, res, next) {
  joi.validate(req.body, userInsertSchema, {'stripUnknown': true}, function(err, validated) {
    if (err) {
      return res.status(500).json({
        'errors': err.details[0].message,
      });
    } else {
      res.locals.user = validated;
      return next();
    }
  });
};

const userSignInSchema = joi.object().keys({
  email: joi.string().min(4).required(),
  password: joi.string().min(8).required(),
});

exports.validateSignInUser = (req, res, next) => {
  joi.validate(req.body, userSignInSchema, {'stripUnknown': true}, function(err, validated) {
    if (err) {
      return res.status(500).json({
        'errors': err.details[0].message,
      });
    } else {
      res.locals.user = validated;
      return next();
    }
  });
};
