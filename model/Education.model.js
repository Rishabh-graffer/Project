const mongoose = require('mongoose');

const experienceSchema = new mongoose.Schema({
  experiences: { type: String, required: true },
  School: { type: String, required: true },
  Degree: { type: String, required: true },
  FieldOfStudy: { type: String, required: true },
  StartYear: { type: String, required: true },
  EndYear: { type: String, required: true },
  Grade: { type: String },
  Description: { type: String },
  userId:{ type: String }
});

const ExperienceModel = mongoose.model('Experience', experienceSchema);

module.exports = ExperienceModel;
