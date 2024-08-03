const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
// const dotenv = require('dotenv').config()
const cors = require('cors');
const {PrismaClient} = require('@prisma/client');
const client = require('./redis');
const { serialize } = require('cookie');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors({
  origin: ['https://buymybeer.vercel.app','http://localhost:3000'], 
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'] // specifying allowed headers
}));
// app.use((req, res, next) => {
//   res.header('Access-Control-Allow-Origin', 'https://buymybeer.vercel.app'); // Allow your client origin
//   res.header('Access-Control-Allow-Credentials', 'true'); // Allow credentials
//   next();
// });


// Secret key for JWT
const JWT_SECRET = process.env.JWT_KEY;

// Register endpoint
app.get('/',(req,res)=>{
    res.send('Hello')
})
app.post('/signup', async(req, res) => {
    const salt = 9;
    const {email,fname,lname,password} = req.body;
    const passw = await bcrypt.hash(password,salt)
    const prismaClient = new PrismaClient()
    var rows = await prismaClient.users.count()
    if(rows < 2){
        let response = await prismaClient.users.create({
            data: {
                'email':email,
                'fname':fname,
                'lname':lname,
                'password':passw
            }
        })
        if(response){
            return res.send({
                status:'success',
                message:'User created successfully'
            })
        }
        return res.send({
            message:'User already exist,Please add different Email Id'
        })
    }else{
        return res.send({
            message:'Reached max limit to create'
        });

    }
});

// Login endpoint
app.post('/login', async(req, res) => {
    const {email,password} = (req.body);
    console.log({email,password});
    const prismaClient = new PrismaClient()
    const user = await prismaClient.users.findUnique({
        where:{
            email
        },
    })
    if(user){
        const compare = await bcrypt.compare(password,user?.password)
        if(compare) {
            const token = jwt.sign({user:req?.body?.email},process.env.JWT_KEY,{expiresIn:'86400s'});
            await client.set('cid',token,{
                EX: 60 * 60 * 24 // Expire after 24 hours
            })
            res.setHeader('Set-Cookie',serialize('cid',token,{
                secure:process.env.NODE_ENV==='production',
                httpOnly:true,
                maxAge:'86400',
                path:'/',
                sameSite: 'None'
            }))
            return res.status(200).json({message:'User logged In successfully!'});
        };
        return res.status(403).json({message:'Invalid credentials'});
    }
    return res.status(401).json({message:'User does not exist'});
});

// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
    res.status(200).json({ message: 'You have accessed a protected route' });
});

app.listen(3000, () => {
    console.log(`Server is running on port ${PORT}`);
});
