const express = require("express");
const mongoose = require("mongoose");
const config = require("./config/key");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { User } = require("./model/User");
const { auth } = require("./middleware/auth");

const port = process.env.NODE_ENV || 5000;
const app = express();

mongoose
  .connect(config.mongoURI, {
    dbName: "blog",
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useNewUrlParser: true,
  })
  .then(() => console.log("db connected..."))
  .catch((err) => console.error(err));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.get("/", (req, res) => res.send("hello world"));

app.post("/api/users/register", (req, res) => {
  const user = new User(req.body);
  user
    .save()
    .then((user) => res.json({ success: true }))
    .catch((err) => res.json({ success: false }));
});

app.post("/api/users/login", (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) {
      res.json({ loginSuccess: false, message: "id 없다" });
    }
    user.comparePassword(req.body.password, (err, result) => {
      if (!result) {
        return res.json({ loginSuccess: false, message: "비밀번호 일치 안함" });
      }
      user.generateToken((err, user) => {
        if (err) {
          return res.json({ loginSuccess: false, err });
        }
        return res
          .cookie("x_auth", user.token)
          .status(200)
          .json({ loginSuccess: true });
      });
    });
  });
});

app.get("/api/users/auth", auth, (req, res) => {
  res.status(200).json({
    _id: req.user._id,
    name: req.user.name,
    email: req.user.email,
    password: req.user.password,
    image: req.user.image,
    token: req.user.token,
    role: req.user.role,
    isAdmin: req.user.role === 0 ? false : true,
    isAuth: true,
  });
});

app.get("/api/users/logout", auth, (req, res) => {
  User.findOneAndUpdate(
    { email: req.user.email },
    { token: "" },
    (err, user) => {
      if (err) {
        return res.json({ success: false, err });
      }
      res.status(200).send({ success: true });
    }
  );
});

app.listen(port, () => console.log(`App is listening on port ${port}`));
