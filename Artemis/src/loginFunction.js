const fs = require('fs');
const {ipcRenderer}=require('electron')
const path=require('path')

let email
let password
let submitButton = document.getElementById("submit");

submitButton.addEventListener("click",()=>{
    const filePath=path.join(__dirname,'user.json')
    let pattern=/^[^\s@]+@[^\s@]+\.[^\s@]+$/
    email=document.getElementById("email").value.toString()
    password=document.getElementById("password").value.toString()
    username=document.getElementById("username").value.toString()
    if(pattern.test(email)){
        let data={
            "username":username,
            "email":email,
            "password":password
        }
        fs.writeFile(filePath,JSON.stringify(data),(err)=>{
            if(err){
                console.log(err);
                throw err
            }
        })
        ipcRenderer.send('navigate','/Users/rachitdas/Desktop/final-app/src/tptp.html')
    }
    else{
        alert("Invalid email")
    }
})

