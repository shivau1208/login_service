const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const {PrismaClient} = require('@prisma/client');
const cookieParser = require('cookie-parser');
const serverless = require('serverless-http')

// const MongoClient = require('mongodb').MongoClient;
// const url = process.env.DATABASE_URL;


require('dotenv').config();

const app = express();
const router = express.Router()
const PORT = process.env.PORT || 5000;


app.use(cookieParser()); // Use cookie-parser middleware
app.use(bodyParser.json());
app.use(cors({
    origin: ['https://login-service-xwdp.onrender.com','https://login-service.netlify.app','http://localhost:3000','https://thebrewedbeers.vercel.app'], 
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'] // specifying allowed headers
}));


// Secret key for JWT
const JWT_SECRET = process.env.JWT_KEY;

// Register endpoint
router.get('/',(req,res)=>{
    res.send('Hello')
})
router.post('/signup', async(req, res) => {
    const {email,fname,lname,password} = req.body;
    const salt = 9;
    const passw = await bcrypt.hash(password,salt)
    const prismaClient = new PrismaClient()
    let rows = await prismaClient.users.count();
    
    if(rows < 11){
        try{
            await prismaClient.users.create({
                data: {
                    'email':email,
                    'fname':fname,
                    'lname':lname,
                    'password':passw
                }
            })
            return res.status(200).json({
                message:'User created successfully'
            })
        }catch(error){
            if (error.code === 'P2002' && error.meta.target.includes('email')) {
                return res.status(409).json({
                    message:'User already exist,Please add different Email Id'
                })
            }
        }
    }else{
        return res.status(400).json({
            message:'Reached max limit to create'
        });

    }
});
router.post('/oauth', async(req, res) => {
    const {email,fname,lname,password,providerId} = req.body;
    const salt = 9;
    const passw = await bcrypt.hash(password,salt)
    const prismaClient = new PrismaClient()
    let rows = await prismaClient.users.count()
    if(rows < 11){
        try{
            await prismaClient.users.create({
                data: {
                    'email':email,
                    'fname':fname,
                    'lname':lname,
                    'password':passw,
                    'provider': providerId
                }
            })
            return res.status(200).json({
                message:'User created successfully'
            })
        }catch(error){
            return res.status(409).json({
                message:'User already exist,Please add different Email Id',error
            })
        }
    }else{
        return res.status(400).json({
            message:'Reached max limit to create'
        });

    }
});

// Login endpoint
router.post('/login', async(req, res) => {
    const {email,password} = (req.body);
    const prismaClient = new PrismaClient()
    try {
        // Find the user by email
        const user = await prismaClient.users.findUnique({
            where: {
                email: email, // assuming email is defined somewhere before
            },
        });
    
        // Check if the user exists
        if (!user) {
            return res.status(401).json({ message: 'User does not exist' });
        }
    
        // Verify the password
        await bcrypt.compare(password, user.password) // make sure password is defined
        .then((response)=>{
            if(response){
                // Generate JWT token
                const token = jwt.sign({ user: email }, process.env.JWT_KEY, { expiresIn: '86400s' });
    
                // Set the token as a cookie
                res.cookie('cid', token, {
                    httpOnly: true,
                    secure: true,
                    maxAge: 86400000, // 1 day in milliseconds
                    path: '/',
                    sameSite: 'None', // required for cross-site cookies
                    partitioned: true,
                });
                return res.status(200).json({ message: 'User logged in successfully!', email:user.email, id:user._id});
            }
            return res.status(403).json({ message: 'Invalid credentials' });
        }).catch(error=>{
            console.error('Error comparing passwords:', error);
            return res.status(500).json({ message: 'Error during login process' });
        })
    } catch (error) {
        console.error('Error finding user:', error);
        return res.status(500).json({ message: 'Error finding user' });
    }
    
});
router.post('/logout', async (req, res) => {
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
        res.status(401).json({ message: 'Unauthorized access' });
    }
};

// Protected route
router.get('/protected', authenticateJWT, (req, res) => {
    res.status(200).json({ message: 'You have accessed a protected route' });
});


app.use('/.netlify/functions/api',router)

module.exports = app
module.exports.handler = serverless(app)

// app.listen(PORT, () => {
//     console.log(`Server is running on port ${PORT}`);
// });
