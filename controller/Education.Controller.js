const ExperienceModel = require("../model/Education.model");

const addExperience= async(req,res)=>{
    try {
        let data = {...req.body}
        data["userId"] = req.userId;
        const experience = await ExperienceModel.create(data)
        if(experience){
            res.json({
                status:200,
                message:"Experience added sucessfully"
            })
        }else{
            res.json({
                status:400,
                message:"Failed to add experience"
            })
        }
       
    } catch (error) {
      console.log("error", error);   
    }
}

const GetAllExperience= async(req,res)=>{
    try {
        const experience = await ExperienceModel.find({userId:req.userId})
        // console.log("{userId:req.userId}", {userId:req.userId});

        res.json({
            status:200,
            message:"result",
            data:experience
        })
    } catch (error) {
      console.log("error", error);   
    }
}

 const getExperienceById = async(req, res) => {
  const data = await  ExperienceModel.findById(req.params.id)
    // , (err, experience) => {
        if (!data) {
          res.status(404).json({ error: 'Experience not found' });
        } else {
            console.log("data", data?.userId, req.userId);
          if (data?.userId !== req.userId) {
            return res.status(403).json({ error: 'Access denied. Unauthorized.' });
          }
          res.status(200).json(data);
        }
    //   });
  }

  const updateExperienceById = async(req, res) => {

    const experience = await  ExperienceModel.findById(req.params.id)

    if (!experience) {
        res.status(404).json({ error: 'Experience not found' });
      } else {
        if (experience?.userId !== req.userId) {
          return res.status(403).json({ error: 'Access denied. Unauthorized.' });
        }
        const data = await ExperienceModel.findByIdAndUpdate(
            req.params.id,
            req.body)
           
              if (!data) {
                res.status(400).json({ error: err.message });
              } else {
                res.status(200).json({message:"updated successfully"});
              }
      }

 
        
      
  }
  

  const deleteExperienceById = async(req, res) => {
    const experience = await  ExperienceModel.findById(req.params.id)

    if (!experience) {
        res.status(404).json({ error: 'Experience not found' });
      } else {
        if (experience?.userId !== req.userId) {
          return res.status(403).json({ error: 'Access denied. Unauthorized.' });
        }
        const data = await ExperienceModel.findByIdAndDelete(
            req.params.id,
            req.body)
           
              if (!data) {
                res.status(400).json({ error: err.message });
              } else {
                res.status(200).json({message:"Deleted successfully"});
              }
      }

  }



module.exports = { addExperience,GetAllExperience, getExperienceById , updateExperienceById,deleteExperienceById };