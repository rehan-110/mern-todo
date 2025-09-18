// api/index.js
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
const app = express();
app.use(express.json());
app.use(cors());
/* ---------- hard-coded config ---------- */
const MONGO_URI = 'mongodb+srv://rehan:rehan@cluster0.rrcgbky.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = 'supersecretkey';
const PORT = 5000;
/* ---------- connect DB ---------- */
mongoose
.connect(MONGO_URI)
.then(() => console.log('MongoDB connected'))
.catch((err) => console.error('Mongo connection error:', err));
/* ---------- schemas ---------- */
const userSchema = new mongoose.Schema({
name:     { type: String, required: true },
email:    { type: String, required: true, unique: true },
password: { type: String, required: true },
});
const todoSchema = new mongoose.Schema({
user:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
title:  { type: String, required: true },
completed: { type: Boolean, default: false },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);
const Todo = mongoose.model('Todo', todoSchema);
/* ---------- helpers ---------- */
const createToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: '7d' });
const auth = async (req, res, next) => {
const header = req.headers.authorization;
if (!header) return res.status(401).json({ message: 'No token provided' });
const token = header.split(' ')[1];
try {
const decoded = jwt.verify(token, JWT_SECRET);
req.user = await User.findById(decoded.id).select('-password');
if (!req.user) return res.status(401).json({ message: 'User not found' });
next();
} catch (e) {
return res.status(401).json({ message: 'Invalid token' });
}
};
/* ---------- routes ---------- */
// health
app.get('/', (_, res) => res.json({ message: 'API running' }));
// signup
app.post('/api/signup', async (req, res) => {
try {
const { name, email, password } = req.body;
if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });

const exists = await User.findOne({ email });
if (exists) return res.status(400).json({ message: 'Email already registered' });

const hashed = await bcrypt.hash(password, 10);
const user = await User.create({ name, email, password: hashed });

res.status(201).json({ message: 'User created', token: createToken(user._id) });
} catch (err) {
res.status(500).json({ message: 'Server error', error: err.message });
}
});
// login
app.post('/api/login', async (req, res) => {
try {
const { email, password } = req.body;
if (!email || !password) return res.status(400).json({ message: 'All fields required' });

const user = await User.findOne({ email });
if (!user) return res.status(400).json({ message: 'Invalid credentials' });

const match = await bcrypt.compare(password, user.password);
if (!match) return res.status(400).json({ message: 'Invalid credentials' });

res.json({ message: 'Login successful', token: createToken(user._id) });
} catch (err) {
res.status(500).json({ message: 'Server error', error: err.message });
}
});
// todos (CRUD)
app.get('/api/todos', auth, async (_req, res) => {
const list = await Todo.find({ user: res.req.user._id }).sort({ createdAt: -1 });
res.json(list);
});
app.post('/api/todos', auth, async (req, res) => {
const { title } = req.body;
if (!title) return res.status(400).json({ message: 'Title required' });
const todo = await Todo.create({ user: res.req.user._id, title });
res.status(201).json(todo);
});
app.put('/api/todos/:id', auth, async (req, res) => {
const { title, completed } = req.body;
const todo = await Todo.findOneAndUpdate(
{ _id: req.params.id, user: res.req.user._id },
{ title, completed },
{ new: true }
);
if (!todo) return res.status(404).json({ message: 'Todo not found' });
res.json(todo);
});
app.delete('/api/todos/:id', auth, async (req, res) => {
const todo = await Todo.findOneAndDelete({ _id: req.params.id, user: res.req.user._id });
if (!todo) return res.status(404).json({ message: 'Todo not found' });
res.json({ message: 'Todo deleted' });
});
/* ---------- serverless + local dual ---------- */
export default app;
/* start local listener only when run directly */
if (!process.env.VERCEL) {
app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
}
