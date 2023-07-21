const express = require("express");
const app = express();
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const path = require("path");


// Config
  require("dotenv").config({ path: "backend/config/config.env" });

app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Route Imports
const educationRoute = require('./route/Education.Route');
const UserRoute = require('./route/User.Route');
const connectDatabase = require("./utils/database");


app.use("/api", educationRoute);
app.use("/api", UserRoute);

app.use(express.static(path.join(__dirname, "../frontend/build")));

app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "../frontend/build/index.html"));
});

// Middleware for Errors
// app.use(errorMiddleware);

connectDatabase();
const server = app.listen(3000, () => {
  console.log(`Server is working on http://localhost:${3000}`);
});

module.exports = app;
