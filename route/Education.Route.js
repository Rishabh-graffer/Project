const app = require("express");
const { addExperience, getExperienceById, updateExperienceById, deleteExperienceById, GetAllExperience } = require("../controller/Education.Controller");
const verifyToken = require("../utils/verifyToken");

const route = app.Router()

route.post("/addexperience",verifyToken, addExperience)
route.get("/experiences/:id",verifyToken, getExperienceById)
route.get("/experiences",verifyToken, GetAllExperience)
route.put("/experiences/:id",verifyToken, updateExperienceById)
route.delete("/experiences/:id",verifyToken, deleteExperienceById)

module.exports = route;