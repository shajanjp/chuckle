const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let userSchema = new Schema({
  username: String,
  email: String,
  firstName: String,
  lastName: String,
  password: String,
  role: String,
  permissions: [String],
});

mongoose.model('user', userSchema);
