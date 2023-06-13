const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log(username, email, password);
    //input validation
    if (!username || !email || !password) {
      return res.status(400).send( req.body.username + " is not a validf");
    }
    //hash password asynchronously
    const hashedPassword = await bcrypt.hash(password, 8);

    const user = new User({
      username: username,
      email: email,
      password: hashedPassword,
    });

    let savedUser = await user.save();

    if (req.body.roles) {
      const roles = await Role.find({ name: { $in: req.body.roles } });
      if (roles.length == 0) {
        throw new Error("Roles not found");
      }
      //use savedUser instead of user
      savedUser.roles = roles.map((role) => role._id);
      await savedUser.save();
    } else {
      let role = await Role.findOne({ name: "user" });
      if (!role) {
        throw new Error("Role not found");
      }
      //use savedUser instead of user
      savedUser.roles = [role._id];
      await savedUser.save();
    }

    res.status(201).json({ message: "User was registered successfully!" });
  } catch (err) {
    //handle errors consistently and gracefully
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
};

exports.signin = (req, res) => {
  User.findOne({
    username: req.body.username,
  })
    .populate("roles", "-__v")
    .exec((err, user) => {
      if (err) {
        res.status(500).send({ message: err });
        return;
      }

      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      const authorities = user.roles.map(
        (role) => `ROLE_${role.name.toUpperCase()}`
      );

      const token = jwt.sign({ id: user.id }, config.secret, {
        expiresIn: 86400, // 24 hours
      });

      req.session.token = token;

      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
      });
    });
};

exports.signout = async (req, res) => {
  try {
    req.session = null;
    return res.status(200).send({ message: "You've been signed out!" });
  } catch (err) {
    this.next(err);
  }
};
