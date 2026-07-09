// TigerGate Vulnerability Test File
// Purpose: SAST + Secrets + Code Quality Testing

const express = require("express");
const mysql = require("mysql");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const child_process = require("child_process");
const fs = require("fs");

const app = express();

app.use(express.json());

// ===============================
// Secrets Detection
// ===============================

const AWS_ACCESS_KEY_ID = "AKIA123456789FAKEKEY";
const AWS_SECRET_ACCESS_KEY = "fakeAWSSecret123456789";
const GITHUB_TOKEN = "ghp_fakegithubtoken123456";
const JWT_SECRET = "supersecretpassword123";

const DB_USER = "admin";
const DB_PASSWORD = "password123";


// ===============================
// Insecure Database Config
// ===============================

const connection = mysql.createConnection({
    host: "localhost",
    user: DB_USER,
    password: DB_PASSWORD,
    database: "users"
});


// ===============================
// SQL Injection
// ===============================

app.get("/user", (req,res)=>{

    let id = req.query.id;

    let query =
    "SELECT * FROM users WHERE id=" + id;

    connection.query(query,(err,result)=>{
        res.send(result);
    });

});


// ===============================
// Command Injection
// ===============================

app.get("/ping",(req,res)=>{

    let host = req.query.host;

    child_process.exec(
        "ping " + host,
        function(error, stdout){

            res.send(stdout);

        }
    );

});


// ===============================
// Weak Cryptography
// ===============================

app.get("/hash",(req,res)=>{

    let password="admin123";

    let hash = crypto
        .createHash("md5")
        .update(password)
        .digest("hex");

    res.send(hash);

});


// ===============================
// Weak JWT
// ===============================

app.get("/token",(req,res)=>{

    let token = jwt.sign(
        {
            user:"admin",
            role:"root"
        },
        JWT_SECRET
    );

    res.send(token);

});


// ===============================
// Path Traversal
// ===============================

app.get("/file",(req,res)=>{

    let filename=req.query.name;

    let data = fs.readFileSync(
        "./files/" + filename
    );

    res.send(data);

});


// ===============================
// XSS Vulnerability
// ===============================

app.get("/search",(req,res)=>{

    let keyword=req.query.q;

    res.send(
        "<h1>Search:"+
        keyword+
        "</h1>"
    );

});


// ===============================
// Sensitive Data Exposure
// ===============================

app.get("/profile",(req,res)=>{


    res.json({

        username:"admin",

        password:"admin123",

        creditCard:
        "4111111111111111",

        token:GITHUB_TOKEN

    });


});



// ===============================
// Missing Authentication
// ===============================

app.delete("/deleteAllUsers",
(req,res)=>{


    res.send(
        "All users deleted"
    );


});



// ===============================
// Insecure Random
// ===============================

app.get("/reset-password",
(req,res)=>{

    let resetToken =
        Math.random()
        .toString();

    res.send(resetToken);


});



// ===============================
// Bad Code Quality
// ===============================


var unusedVariable =
"never used";


function duplicate(){

console.log("duplicate");

}


function duplicate2(){

console.log("duplicate");

}



// Long messy function

function processEverything(){

let a=1;
let b=2;
let c=3;

console.log(a);
console.log(b);
console.log(c);

if(a){

 if(b){

  if(c){

   console.log(
    "nested callback hell"
   );

  }

 }

}

}


// ===============================
// Bad CORS
// ===============================

app.use(function(req,res,next){

res.header(
"Access-Control-Allow-Origin",
"*"
);

next();

});



// ===============================
// Server
// ===============================

app.listen(
3000,
()=>{

console.log(
"Vulnerable app running"
);

});