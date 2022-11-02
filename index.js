
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { MongoClient, ObjectId } from "mongodb";
import { userRouter } from "./router/user.js";
import { CheckPassword, createUser, GenHasPassword,Idchecker } from "./router/helper.js"
import nodemailer from "nodemailer";


const app = express()

dotenv.config()

app.use(cookieParser())

app.use(express.json())
app.use(bodyParser.json({limit:"30mb",extended:true}))
app.use(bodyParser.urlencoded({limit:"30mb",extended:true}))

app.use(cors())

const PORT = process.env.PORT;

const Mongo_url=process.env.MONGOURL

async function CreateConnection(){
    const Client = new MongoClient(Mongo_url);
    Client.connect;
    console.log('Mongo connected')
    return Client
}

export const Client = await CreateConnection()

app.get("/",(req,res)=>{
   res.send("backend server connected")
})

app.post("/signup",async(req,res)=>{
    const {name,email,password}=req.body
    const IsTheres = await Idchecker(email)
    if(!IsTheres){
        const hashed = await GenHasPassword(password)
        const result = await createUser({
            name,
            email,
            password:hashed
        })
        res.send(result)
    }else{
        res.send("EmailId Already Exist")
    }
    
})

app.post("/login",async(req,res)=>{
    const {email,password}=req.body;
    try{
        const IsThere = await Idchecker(email)
        if(IsThere){
           
            const correct_password = await CheckPassword(password,IsThere.password)
           
            if(correct_password){
                // res.send("password accepted")
                const token = jwt.sign({email:IsThere.email,id:IsThere._id},process.env.SC,{expiresIn:"1h"});
                res.cookie("token", token, {
                    expires: new Date(Date.now() + 86000000),
                    httpOnly: true,
                    secure: true,
                    sameSite: "none",
                  });
                    res.status(200).json({result:IsThere,token})
                    // res.status(200).send({result:IsThere,token})
            }
            else{
                res.send("password incorrect")
            }
        }else{
             res.send("emailId Not Exist")
        }
    }catch(err){
        console.log(err.message)
    }
})

app.post("/forgetpassword",async (req,res)=>{
    const {email}=req.body
    try{
        const UserExist = await Idchecker(email)

        if(!UserExist){
            res.send("User Not Exist")
        }else{
            const Key = process.env.SC + UserExist.password

            const token = jwt.sign({email:email,id:UserExist._id},Key,{
                expiresIn:"1h"
            })
            const CreateLink=`http://localhost:5000/resetpassword/${UserExist._id}/${token}`

            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                  user: process.env.Email_ID,
                  pass: process.env.Password
                }
              });
              
              var mailOptions = {
                from: 'youremail@gmail.com',
                to: UserExist.email,
                subject: 'Sending New password',
                text: CreateLink
              };
              
              transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                  console.log(error);
                } else {
                  console.log('Email sent: ' + info.response);
                }
              });
                res.send("check Your Email-Id for New password")

        }

    }catch(err){
        console.log(err.message)
    }
})

app.get("/resetpassword/:id/:token",async (req,res)=>{
    const {id,token}=req.params;
    const UserExist = await Client.db('MailApp').collection("user").findOne({_id:ObjectId(id)})
    if(!UserExist){
        return res.json({status:"User Not Exist"})

    }else{

        try{
            const Key= process.env.SC + UserExist.password
            const CheckToken = jwt.verify(token,Key)
            if(!CheckToken){
                res.send("Invalide Token")
            }else{
                const NewPassword=  Math.random().toString(36).substring(2,7)
                const hashed = await GenHasPassword(NewPassword)
                 await Client.db('MailApp').collection("user").updateOne({_id:ObjectId(id)},{
                    $set:{
                        email:UserExist.email,
                        password:hashed
                    }
                })
                res.send(NewPassword)
            }
        }catch(err){
            console.log(err.message)
        }
    }
})


app.post("/mailsend",async (req,res)=>{
    const {sender_email,receiver_email,subject,mail_content}=req.body;
    
try{

    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
        //   user: process.env.Email_ID,
          user: process.env.Email_ID,
          pass: process.env.Password
        }
      });
      
      var mailOptions = {
        // from: "youremail@gmail.com",
        from:sender_email,
        to: receiver_email,
        subject: subject,
        text: mail_content
      };
      
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });
      res.send("check Your Email-Id for New password")
}
catch(err){
    console.log(err)
}
        //   res.send({subject:subject,content:mail_content})

   
   
})




// app.use("/users",userRouter)

app.listen(PORT,()=> console.log(`connected in port of ${PORT}`))