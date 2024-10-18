const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const {PrismaClient} = require('@prisma/client');
const { serialize } = require('cookie');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cookieParser()); // Use cookie-parser middleware
app.use(bodyParser.json());
app.use(cors({
    origin: ['https://login-service-xwdp.onrender.com','http://localhost:3000','https://buymybeer.vercel.app'], 
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'] // specifying allowed headers
}));

// Secret key for JWT
const JWT_SECRET = process.env.JWT_KEY;
const prismaClient = new PrismaClient()
// Register endpoint
app.get('/',(req,res)=>{
    res.send('Hello')
})
app.post('/signup', async(req, res) => {
    const salt = 9;
    const {email,fname,lname,password} = req.body;
    const passw = await bcrypt.hash(password,salt)
    var rows = await prismaClient.users.count()
    if(rows < 11){
        let response = await prismaClient.users.create({
            data: {
                'email':email,
                'fname':fname,
                'lname':lname,
                'password':passw
            }
        })
        if(response){
            return res.status(200).json({
                message:'User created successfully'
            })
        }
        return res.status(409).json({
            message:'User already exist,Please add different Email Id'
        })
    }else{
        return res.status(400).json({
            message:'Reached max limit to create'
        });

    }
});
app.post('/oauth', async(req, res) => {
    const {email,fname,lname,password,providerId} = req.body;
    var rows = await prismaClient.users.count()
    if(rows < 11){
        let response = await prismaClient.users.create({
            data: {
                'email':email,
                'fname':fname,
                'lname':lname,
                'password':password,
                'provider': providerId
            }
        })
        if(response){
            return res.status(200).json({
                message:'User created successfully'
            })
        }
        return res.status(409).json({
            message:'User already exist,Please add different Email Id'
        })
    }else{
        return res.status(400).json({
            message:'Reached max limit to create'
        });

    }
});

// Login endpoint
app.post('/login', async(req, res) => {
    const {email,password} = (req.body);
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
            res.cookie('cid',token,{
                httpOnly:true,
                secure:true,
                maxAge:86400000,
                path:'/',
                sameSite:'None',
                partitioned: true
            })
            return res.status(200).json({message:'User logged In successfully!'});
        };
        return res.status(403).json({message:'Invalid credentials'});
    }
    return res.status(401).json({message:'User does not exist'});
});

app.get('/logout', async (req, res) => {
    try {
        // Clear the cookie
        res.clearCookie('cid', {
            httpOnly: true,      // Ensures cookie is only accessible by the web server
            secure: true,        // Ensures the cookie is only sent over HTTPS
            path: '/',           // Specify the path the cookie applies to
            sameSite: 'None',     // To allow third-party usage, 'None' is required for cross-origin
            partitioned: true     // Match the partitioned attribute
        });
        return res.status(200).json({ message: 'User logged out successfully!' });
    } catch (err) {
        return res.status(403).json({ message: 'Error in logging out' });
    }
});

// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.cid;
    if (!token) {
        return res.status(401).json({ message: 'Malformed token' });
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

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
