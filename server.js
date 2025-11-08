const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const app = express();
const PORT = process.env.PORT || 3000;

// تنظیمات
app.use(express.json());
app.use(express.static(__dirname)); // فایل‌های استاتیک از ریشه

// اطلاعات ادمین
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = '$2a$10$8K1p/a0dRTlB0VZ4q2Qwz.O4gZc6M3QYkS8rJ6t8L5N4v1E2sW'; // GoldCoinSecure123!

// بررسی ادمین
function checkAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Admin Access"');
        return res.status(401).json({ error: 'Authentication required' });
    }

    const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
    const [username, password] = credentials.split(':');

    if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_PASSWORD)) {
        next();
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}

// خواندن داده‌ها
function readData() {
    try {
        const data = fs.readFileSync(path.join(__dirname, 'data.json'), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { users: [], transactions: [] };
    }
}

// ذخیره داده‌ها
function saveData(data) {
    fs.writeFileSync(path.join(__dirname, 'data.json'), JSON.stringify(data, null, 2));
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html')); // فایل از ریشه
});

// پنل مدیریت - امن
app.get('/admin/data', checkAdminAuth, (req, res) => {
    const data = readData();
    res.json(data);
});

// ثبت کاربر جدید
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    const data = readData();
    
    // بررسی وجود کاربر
    if (data.users.find(user => user.email === email)) {
        return res.status(400).json({ error: 'User already exists' });
    }

    // اضافه کردن کاربر
    const newUser = {
        id: Date.now().toString(),
        name,
        email,
        password: bcrypt.hashSync(password, 10),
        coins: 1000, // سکه شروع
        level: 1,
        joinDate: new Date().toISOString()
    };

    data.users.push(newUser);
    saveData(data);

    res.json({ success: true, user: { id: newUser.id, name: newUser.name, coins: newUser.coins } });
});

// ورود کاربر
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const data = readData();
    
    const user = data.users.find(u => u.email === email);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ 
        success: true, 
        user: { 
            id: user.id, 
            name: user.name, 
            email: user.email,
            coins: user.coins,
            level: user.level
        } 
    });
});

// آپدیت کاربر
app.post('/api/user/update', (req, res) => {
    const { userId, coins, level } = req.body;
    const data = readData();
    
    const userIndex = data.users.findIndex(u => u.id === userId);
    if (userIndex === -1) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (coins !== undefined) data.users[userIndex].coins = coins;
    if (level !== undefined) data.users[userIndex].level = level;
    
    saveData(data);
    res.json({ success: true, user: data.users[userIndex] });
});

// راه‌اندازی سرور
app.listen(PORT, () => {
    console.log(`🚀 Gold Coin Server running on port ${PORT}`);
    console.log(`🔒 Admin Panel: https://your-app.onrender.com/admin/data`);
    console.log(`👤 Admin Username: admin`);
    console.log(`🔑 Admin Password: GoldCoinSecure123!`);
});

module.exports = app;
