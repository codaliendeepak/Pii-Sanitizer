const express  = require('express');
const {Sanitizer} = require('../dist/index.js');
const bodyParser = require('body-parser');

const sanitizer = new Sanitizer({
    signingSecret:"thisisseceretkeyforme",
    fieldsToSanitize: ["password", "email","aadhar","mobile"],
})
const app = express();
app.use(bodyParser.json());
app.use(sanitizer.expressMiddleware());

app.post("/test",(req,res)=>{
    return res.json({body:req.body})
})

app.listen(5000);