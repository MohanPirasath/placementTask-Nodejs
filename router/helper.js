import { Client } from "../index.js";
import bcrypt from "bcrypt";

export async function createUser(data){
  const user=  await Client.db('MailApp').collection("user").insertOne(data)
  return user
}

export async function GenHasPassword(password){
  const  no_of_rounds=10
  const salt =await bcrypt.genSalt(no_of_rounds)
  const hashed= await bcrypt.hash(password,salt)
  return hashed
}

export async function Idchecker(email){
    return await Client.db('MailApp').collection("user").findOne({email:email})
  
}

export async function CheckPassword(password,oldpassword){
    
     const correct=await bcrypt.compare(password,oldpassword)
if(correct){
    return true
}else{
    return false
}
   
}














