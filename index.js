const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('@prisma/client').PrismaClient;
const app = express();
const prismaClient = new prisma();

// Middleware to parse JSON
app.use(express.json());

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret';

// Registration Route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user already exists
  const existingUser = await prismaClient.user.findUnique({
    where: { email },
  });
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prismaClient.user.create({
    data: {
      email,
      password: hashedPassword,
    },
  });

  res.status(201).json({ id: user.id, email: user.email });
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await prismaClient.user.findUnique({
    where: { email },
  });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Compare the entered password with the hashed password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ token });
});

// Authentication Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Add the user info to the request object
    next();
  } catch (error) {
    return res.status(400).json({ error: 'Invalid token' });
  }
};

// Protected Route (Example: Getting Notes)
app.get('/notes', authMiddleware, async (req, res) => {
  const notes = await prismaClient.note.findMany({
    where: { userId: req.user.userId },
  });
  res.json(notes);
});

// Start the Express Server
const port = 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
// Create a new note
app.post('/notes', authMiddleware, async (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.userId;
  
    const newNote = await prismaClient.note.create({
      data: {
        title,
        content,
        userId,
      },
    });
  
    res.status(201).json(newNote);
  });
  