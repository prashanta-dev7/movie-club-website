const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'movie-club-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/movieclub';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    membership: {
        type: { type: String, enum: ['none', 'basic', 'premium'], default: 'none' },
        expiryDate: Date
    },
    createdAt: { type: Date, default: Date.now }
});

// Movie Schema
const movieSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    genre: { type: String, required: true },
    duration: { type: Number, required: true }, // in minutes
    rating: { type: String, required: true },
    posterUrl: { type: String },
    showTimes: [{
        date: Date,
        time: String,
        availableSeats: { type: Number, default: 100 },
        price: { type: Number, required: true }
    }],
    createdAt: { type: Date, default: Date.now }
});

// Booking Schema
const bookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    movieId: { type: mongoose.Schema.Types.ObjectId, ref: 'Movie', required: true },
    showTime: {
        date: Date,
        time: String
    },
    seats: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'confirmed', 'cancelled'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Movie = mongoose.model('Movie', movieSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// AUTH ROUTES

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                membership: user.membership
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                membership: user.membership
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// MOVIE ROUTES

// Get all movies (public)
app.get('/api/movies', async (req, res) => {
    try {
        const movies = await Movie.find().sort({ createdAt: -1 });
        res.json(movies);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single movie (public)
app.get('/api/movies/:id', async (req, res) => {
    try {
        const movie = await Movie.findById(req.params.id);
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }
        res.json(movie);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create movie (admin only)
app.post('/api/movies', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const movie = new Movie(req.body);
        await movie.save();
        res.status(201).json({ message: 'Movie created successfully', movie });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update movie (admin only)
app.put('/api/movies/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const movie = await Movie.findByIdAndUpdate(
            req.params.id, 
            req.body, 
            { new: true }
        );
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }
        res.json({ message: 'Movie updated successfully', movie });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete movie (admin only)
app.delete('/api/movies/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const movie = await Movie.findByIdAndDelete(req.params.id);
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }
        res.json({ message: 'Movie deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// BOOKING ROUTES

// Create booking
app.post('/api/bookings', authenticateToken, async (req, res) => {
    try {
        const { movieId, showTime, seats } = req.body;
        
        // Find movie and check availability
        const movie = await Movie.findById(movieId);
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }

        // Find the specific showtime
        const selectedShowTime = movie.showTimes.find(st => 
            st.date.toDateString() === new Date(showTime.date).toDateString() && 
            st.time === showTime.time
        );

        if (!selectedShowTime) {
            return res.status(404).json({ error: 'Showtime not found' });
        }

        if (selectedShowTime.availableSeats < seats) {
            return res.status(400).json({ error: 'Not enough seats available' });
        }

        // Calculate total amount
        const totalAmount = selectedShowTime.price * seats;

        // Create booking
        const booking = new Booking({
            userId: req.user.userId,
            movieId,
            showTime,
            seats,
            totalAmount
        });

        await booking.save();

        // Update available seats
        selectedShowTime.availableSeats -= seats;
        await movie.save();

        res.status(201).json({ message: 'Booking created successfully', booking });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user bookings
app.get('/api/bookings', authenticateToken, async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.user.userId })
            .populate('movieId')
            .sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ADMIN ROUTES

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user membership (admin only)
app.put('/api/admin/users/:id/membership', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { membershipType, expiryDate } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            {
                'membership.type': membershipType,
                'membership.expiryDate': expiryDate
            },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User membership updated successfully', user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all bookings (admin only)
app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .populate('userId', 'name email')
            .populate('movieId')
            .sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access your website at: http://localhost:${PORT}`);
});

// Create default admin user on startup
const createDefaultAdmin = async () => {
    try {
        const adminExists = await User.findOne({ email: 'admin@movieclub.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = new User({
                name: 'Admin',
                email: 'admin@movieclub.com',
                password: hashedPassword,
                role: 'admin'
            });
            await admin.save();
            console.log('Default admin created: admin@movieclub.com / admin123');
        }
    } catch (error) {
        console.log('Error creating default admin:', error.message);
    }
};

// Initialize default admin when database connects
mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB');
    createDefaultAdmin();
});