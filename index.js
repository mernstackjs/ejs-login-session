require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const PORT = process.env.PORT;
const session = require("express-session");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");
const app = express();

app.use(
  session({
    secret: "ahmed",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URL,
    }),
  })
);
app.get("/session", (req, res) => {
  res.send(req.sessionID);
});
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => console.log("DB is connected"))
  .catch((error) => console.log(error));

const userschema = mongoose.Schema({
  username: String,
  email: String,
  password: String,
});
const User = mongoose.model("User", userschema);
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// This middleware checks if the user is authenticated by verifying the presence of userID in the session
const authenticateUser = (req, res, next) => {
  if (req.session.userID) {
    // User is authenticated
    next();
  } else {
    // User is not authenticated, redirect to login or handle accordingly
    res.redirect("/login");
  }
};

app.get("/logout", (req, res) => {
  // Destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.send("Error during logout");
    } else {
      res.redirect("/login"); // Redirect to the login page after logout
    }
  });
});
app.get("/dashboard", authenticateUser, async (req, res) => {
  try {
    // Access user-specific data from the session
    const userId = req.session.userID;

    // Perform additional actions with userId, such as fetching user details from the database
    const user = await User.findById(userId);

    // Render the dashboard with user data
    res.render("dashboard", { user: user.username });
  } catch (error) {
    console.error("Error accessing session data:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/", (req, res) => {
  res.render("index");
  console.log(req.session.userID);
});
app.get("/login", (req, res) => {
  res.render("login");
});
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.send("User not found");

    const isCompare = await bcrypt.compare(password, user.password);
    if (!isCompare) return res.send("Incorrect password");

    // Set session before redirecting to the dashboard
    req.session.userID = user._id;

    // Redirect to the dashboard after a successful login
    res.redirect("/dashboard");
  } catch (error) {
    res.send(error);
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const isFound = await User.findOne({ email });
    if (isFound) return res.send("this user is already registerd");
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
    });

    res.json(user);
  } catch (error) {
    res.send(error);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
