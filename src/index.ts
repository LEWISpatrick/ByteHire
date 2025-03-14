import { Role } from "@prisma/client";

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();



const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

app.use(express.json()); // Allows Express to parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parses form-encoded data


const bitcoin = require('bitcoinjs-lib');

const { ECPairFactory } = require('ecpair');
const tinysecp = require('tiny-secp256k1');

const ECPair = ECPairFactory(tinysecp);


const JWT_SECRET = process.env.JWT_SECRET;  // Make sure you have this in your .env file

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(cookieParser())


const redirectIfAuthenticated = (
  req: { cookies: { auth_token: any; }; originalUrl: string; },
  res: { redirect: (arg0: string) => any; },
  next: () => void) => {

  const token = req.cookies.auth_token;

    console.log('run redirectIfAuthenticated')

  if (token) {
      jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
          if (user) {
            console.log('found TOKEEN')

            if (req.originalUrl !== "/dashboard") {
                return res.redirect('/dashboard'); // Redirect if token is valid
            }

            return next();
          }
          next(); // Proceed if token is invalid
      });
  } else {
    console.log('no token')

      next(); // Proceed if no token
  }
};



app.get('/', redirectIfAuthenticated, (req: any, res: { sendFile: (arg0: any) => void; }) => {
  res.sendFile(path.resolve(__dirname, "./views/index.html"))
});

app.get('/signup', redirectIfAuthenticated, (req: any, res: { sendFile: (arg0: any) => void; }) => {
  res.sendFile(path.resolve(__dirname, "./views/signup.html"))
});

app.get('/dashboard', redirectIfAuthenticated, (req: any, res: { sendFile: (arg0: any) => void; }) => {
  res.sendFile(path.resolve(__dirname ,'./views/dashboard.html'))
})

app.get('/profile', (req: any, res: { sendFile: (arg0: any) => void; }) => {
    res.sendFile(path.resolve(__dirname ,'./views/profile.html'))
  })
console.log('app ran')


app.listen(port,() => {
    console.log(`Server is running at http://localhost:${port}`);
})












app.post('/signup', async (req: { body: { username: any; password: any; email: any; role: any; }; }, res: { status: (arg0: number) => { (): any; new(): any; json: { (arg0: { message: string; user?: { id: any; username: any; email: any; password: any; publicKey: any; createAt: any; role: any; }; }): void; new(): any; }; }; }) => {

  console.log('started the signup function')

  const { username, password, email , role} = req.body


  if (!username || !password || !email || !role) {
      return res.status(400).json({message: 'Username and password were not filled dumbass'})
  }


  try {
      const hashedPassword = await bcrypt.hash(password, 10) 

      const existingUser = await prisma.user.findUnique({
          where: { email }
      })

      if (existingUser) {
          return res.status(400).json({message: 'bro you already signup stupid!'})

      }

      const keypair = ECPair.makeRandom();


      const { address } = bitcoin.payments.p2pkh({
          pubkey: Buffer.from(keypair.publicKey)
      });

      const privateKey = keypair.toWIF();





      const user = await prisma.user.create({
          data: {
              username,
              email,
              role : role,
              password: hashedPassword,
              publicKey: address,
              privateKey: privateKey

          }
      })





      res.status(201).json({
          message: 'user created W',

          user : {
              id: user.id,
              username: user.username,
              email: user.email,
              role: Role.developer,
              password: user.password,
              publicKey: user.address,
              createAt: user.createdAt
          },
      });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
  }
});



app.post('/login', async (req: { body: { password: any; email: any; }; }, res: { status: (arg0: number) => { (): any; new(): any; json: { (arg0: { message: string; }): void; new(): any; }; }; cookie: (arg0: string, arg1: any, arg2: { httpOnly: boolean; secure: boolean; sameSite: string; maxAge: number; }) => void; redirect: (arg0: string) => any; }) => {
  const {  password, email } = req.body;


  console.log()
  // Validate input
  if (!password || !email) {
      return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
      // Check if username exists
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
          return res.status(401).json({ message: 'Invalid Email or password.' });
      }

      // Check if password matches
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
          return res.status(401).json({ message: 'Invalid Email or password.' });
      }

      // Create a JWT token
      const token = jwt.sign(
          { userId: user.id, username: user.email },
          JWT_SECRET,
          { expiresIn: '1h' }
      );

      // Send token in an HttpOnly cookie
      res.cookie('auth_token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 3600000,
      });
      
      // Respond with success
      return res.redirect('/dashboard')
  } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Internal server error' });
  }
});

// Logout route
app.post('/logout', (req: any, res: { clearCookie: (arg0: string) => void; status: (arg0: number) => { (): any; new(): any; json: { (arg0: { message: string; }): void; new(): any; }; }; }) => {
 console.log('started the logout')
  res.clearCookie('auth_token');  // Remove the token cookie
  res.status(200).json({ message: 'Logged out successfully' });
});



// shit
