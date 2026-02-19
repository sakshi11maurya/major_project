const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('static'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const users = [
  { id: 1, username: 'admin', password: bcrypt.hashSync('AdminPass123!', 10), role: 'admin' },
  { id: 2, username: 'user', password: bcrypt.hashSync('UserPass123!', 10), role: 'user' }
];

const SECRET_KEY = 'your-secret-key';

function validatePassword(password) {
  return password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password);
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!validatePassword(password)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters with uppercase, lowercase, and number.' });
  }
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token, role: user.role });
});

app.post('/logout', (req, res) => {
  // In a real app, invalidate token on server-side (e.g., blacklist)
  res.json({ message: 'Logged out' });
});

app.get('/dashboard', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ message: `Welcome ${decoded.role}`, data: 'Dashboard content' });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
