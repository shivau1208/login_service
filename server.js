const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const bodyParser = require('body-parser');
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const cookieParser = require("cookie-parser");
const serverless = require("serverless-http");
const admin = require("firebase-admin");

require("dotenv").config();

const app = express();
const router = express.Router();
const PORT = process.env.PORT || 5000;

app.use(cookieParser()); // Use cookie-parser middleware
app.use(express.json());
app.use(
	cors({
		origin: ["https://login-service.netlify.app", /^http:\/\/localhost:\d+$/, "https://thebrewedbeers.vercel.app","https://commentservice-qtdfocztwa-el.a.run.app","https://comments-section-frontend-qtdfocztwa-el.a.run.app"],
		credentials: true,
		allowedHeaders: ["Content-Type", "Authorization"],
	})
);

// Secret key for JWT
const JWT_SECRET = process.env.JWT_KEY;

admin.initializeApp({
	credential: admin.credential.applicationDefault(),
	projectId: process.env.FIREBASE_PROJECT_ID, // Make sure this env variable is set to your Firebase project ID
});

// Register endpoint
router.get("/", (req, res) => {
	res.send("Hello");
});

router.post("/oauth", async (req, res) => {
	const authHeader = req.headers.authorization || "";
	const token = authHeader.split("Bearer ")[1];
  const prismaClient = new PrismaClient();
	
	try {
		const oauthUser = await admin.auth().verifyIdToken(token);
        
		// Find the user by email
		const user = await prismaClient.users.findUnique({
			where: {
				email: oauthUser.email, // assuming email is defined somewhere before
			},
		});

		// Check if the user exists
		if (!user) {
			try {
				await prismaClient.users.create({
					data: {
						email: oauthUser.email,
						firstname: oauthUser["name"].split(" ")[0],
						lastname: oauthUser["name"].split(" ")[1],
						photoUrl: oauthUser.picture,
						uid: oauthUser.uid,
						provider: oauthUser.firebase.sign_in_provider,
					},
				});
				// Generate JWT token
				const signedToken = jwt.sign({ email: oauthUser.email, uid: oauthUser.uid, role: "USER" }, process.env.JWT_KEY, { expiresIn: "400d" });

				// Set the token as a cookie
				res.cookie("cid", signedToken, {
					// httpOnly: true,
					secure: true,
					maxAge: 1000 * 60 * 60 * 24 * 400, // 400 days in milliseconds
					path: "/",
					sameSite: "None", // required for cross-site cookies
					// partitioned: true,
				});
				return res.status(200).json({
					message: "User logged in successfully!",
					user: {
						email: oauthUser.email,
						localId: oauthUser.uid,
						firstName: oauthUser.fname,
						lastName: oauthUser.lname,
					},
				});
			} catch (error) {
				console.log("error creating user", error);
			}
		}

		// Generate JWT token
		const signedToken = jwt.sign({ email: user.email, uid: user.uid, role: user.role }, process.env.JWT_KEY, { expiresIn: "400d" });
		
		// Set the token as a cookie
		res.cookie("cid", signedToken, {
			// httpOnly: true,
			secure: true,
			maxAge: 1000 * 60 * 60 * 24 * 400, // 400 days in milliseconds
			path: "/",
			sameSite: "None", // required for cross-site cookies
			// partitioned: true,
		});
		return res.status(200).json({
			message: "User logged in successfully!",
			user: {
				email: user.email,
				localId: user.uid,
				firstName: user.fname,
				lastName: user.lname,
			},
		});
	} catch (error) {
		console.error("Error finding user:", error);
		return res.status(500).json({ message: "Error finding user" });
	}
});

router.post("/logout", async (req, res) => {
	try {
		// Clear the cookie
		res.clearCookie("cid", {
			httpOnly: true, // Ensures cookie is only accessible by the web server
			secure: true, // Ensures the cookie is only sent over HTTPS
			path: "/", // Specify the path the cookie applies to
			sameSite: "None", // To allow third-party usage, 'None' is required for cross-origin
			partitioned: true, // Match the partitioned attribute
		});
		return res.status(200).json({ message: "User logged out successfully!" });
	} catch (err) {
		return res.status(403).json({ message: "Error in logging out" });
	}
});

// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
	const token = req.cookies.cid;
	if (!token) {
		return res.status(401).json({ message: "Malformed token" });
	}

	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = decoded;
		next();
	} catch (error) {
		res.status(401).json({ message: "Unauthorized access" });
	}
};

// Protected route
router.get("/protected", authenticateJWT, (req, res) => {
	res.status(200).json({ message: "You have accessed a protected route" });
});

app.use("/.netlify/functions/api", router);

module.exports = app;
module.exports.handler = serverless(app);


app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
