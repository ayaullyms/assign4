require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const methodOverride = require('method-override');
const path = require('path');
const User = require('./models/User'); 
const app = express();

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  })
  .then(() => console.log('MongoDB Atlas connected'))
  .catch(err => console.error('MongoDB connection error:', err));

//Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true })); //parse form data
app.use(express.json());
app.use(methodOverride('_method')); // for put/delete 
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user;
  next();
});

//Access control middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

//Role-based Access Middleware 
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).send('Access Denied');
}

//Account Locking
const MAX_FAILED_ATTEMPTS = 5;

// Home page
app.get('/', (req, res) => {
  res.render('index');
});

// Registration Form
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Handle registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username ||  !email ||  !password || password.length < 6) {
    return res.render('register', { error: 'All fields are required and password must be at least 6 characters.' });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('register', { error: 'Email already registered.' });
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 12);
    // Create new user 
    const user = new User({ username, email, password: hashedPassword, role: 'user', failedAttempts: 0 });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Registration failed. Try again.' });
  }
});

// Login Form
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Handle Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('login', { error: 'Both email and password are required.' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) return res.render('login', { error: 'User not found.' });
    if (user.isLocked) {
      return res.render('login', { error: 'Your account is locked due to too many failed attempts.' });
    }
    const match = await bcrypt.compare(password, user.password);


if (!match) {
    // Increment failed attempts
    user.failedAttempts = user.failedAttempts + 1;
    if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      user.isLocked = true;
    }
    await user.save();
    return res.render('login', { error: 'Incorrect password.' });
  }
  // Reset failed attempts on successful login
  user.failedAttempts = 0;
  user.isLocked = false;
  await user.save();

  // Save user data  
  req.session.user = { id: user._id, username: user.username, email: user.email, role: user.role };
  res.redirect('/dashboard');
} catch (err) {
  console.error(err);
  res.render('login', { error: 'Login failed. Try again.' });
}
});

// Dashboard 
app.get('/dashboard', isAuthenticated, (req, res) => {
res.render('dashboard', { user: req.session.user });
});

// Restricted admin page
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
res.send('Welcome Admin!');
});

// Logout
app.post('/logout', (req, res) => {
req.session.destroy(err => {
  if (err) console.error(err);
  res.redirect('/');
});
});

//Admin
app.get('/makeadmin', async (req, res) => {
  try {

    const email = "ayaulym@example.com"; 
    const updatedUser = await User.findOneAndUpdate(
      { email },
      { role: "admin" },
      { new: true }
    );
    res.send(`User ${updatedUser.username} is admin.`);
  } catch (err) {
    console.error(err);
    res.send("Error");
  }
});

//CRUD: edit user profile 
app.get('/profile/edit', isAuthenticated, async (req, res) => {
const user = await User.findById(req.session.user.id);
res.render('editProfile', { user, error: null });
});

app.put('/profile', isAuthenticated, async (req, res) => {
const { username, email } = req.body;
if (!username || !email) {
  return res.render('editProfile', { user: req.session.user, error: 'All fields are required.' });
}
try {
  const user = await User.findByIdAndUpdate(req.session.user.id, { username, email }, { new: true });
  // Update info
  req.session.user.username = user.username;
  req.session.user.email = user.email;
  res.redirect('/dashboard');
} catch (err) {
  console.error(err);
  res.render('editProfile', { user: req.session.user, error: 'Failed to update profile.' });
}
});

// Delete 
app.delete('/profile', isAuthenticated, async (req, res) => {
try {
  await User.findByIdAndDelete(req.session.user.id);
  req.session.destroy(err => {
    if (err) console.error(err);
    res.redirect('/');
  });
} catch (err) {
  console.error(err);
  res.redirect('/dashboard');
}
});

// Catch-all error route
app.use((req, res) => {
res.status(404).render('error', { message: 'Page not found' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
