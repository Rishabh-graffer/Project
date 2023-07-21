const app = require("express");
const { AddUser, login } = require("../controller/User.Controller");

const route = app.Router()

route.post("/signup", AddUser)
route.post("/login", login)

module.exports = route;