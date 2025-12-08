// auth_api/server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors'); 
require('dotenv').config(); // Для загрузки JWT_SECRET из .env локально

const app = express();
const port = process.env.PORT || 3000; // Динамический порт для хостинга
const SALT_ROUNDS = 10;
const SECRET_KEY = process.env.JWT_SECRET; 

if (!SECRET_KEY) {
    console.error("КРИТИЧЕСКАЯ ОШИБКА: JWT_SECRET не установлен. Проверьте .env или настройки хостинга.");
    process.exit(1); 
}

// --- УПРОЩЕННАЯ "БД" В ПАМЯТИ ---
let nextUserId = 2; 
const usersDB = [
    // Хешированный пароль '123456'
    { id: 1, name: 'Студент Тест', email: 'test@vuz.ru', hashedPassword: '$2b$10$wTf2A2jD7zQfG/J0yK8X9Oa5iB3C2D1E0F9G8H7I6J5K4L3M2N1O0' }
];

// --- НАСТРОЙКА CORS (Критично для работы на разных доменах) ---
// ВНИМАНИЕ: Замените заглушку на реальный публичный домен вашего фронтенда (например, https://vuz-portal.vercel.app)
const allowedOrigins = [
    // !!! ДОЛЖЕН БЫТЬ ТОЧНО ЭТОТ АДРЕС ИЗ КОНСОЛИ !!!
    'https://fanciful-gingersnap-d87b1c.netlify.app', 
    
    'http://localhost:3000', 
    'http://localhost:5500', 
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin) || origin.endsWith('vercel.app')) { // Vercel/Netlify previews
            callback(null, true);
        } else {
            callback(new Error('CORS Policy Blocked'));
        }
    }
};

app.use(cors(corsOptions)); 
app.use(express.json()); 


// --- 1. МАРШРУТ РЕГИСТРАЦИИ ---
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (usersDB.find(u => u.email === email)) {
        return res.status(409).json({ success: false, message: 'Этот Email уже зарегистрирован.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = { id: nextUserId++, name, email, hashedPassword };
        usersDB.push(newUser);
        res.status(201).json({ success: true, message: 'Регистрация успешна.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Ошибка сервера.' });
    }
});

// --- 2. МАРШРУТ АВТОРИЗАЦИИ ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = usersDB.find(u => u.email === email);
    if (!user) return res.status(401).json({ success: false, message: 'Неверные данные.' });

    try {
        const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
        if (!isPasswordValid) return res.status(401).json({ success: false, message: 'Неверные данные.' });

        const token = jwt.sign(
            { id: user.id, name: user.name }, 
            SECRET_KEY, 
            { expiresIn: '1d' } // Токен действует 1 день
        );

        return res.status(200).json({ success: true, token: token });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Ошибка сервера.' });
    }
});

// --- MIDDLEWARE ПРОВЕРКИ JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (token == null) return res.sendStatus(401); 

    jwt.verify(token, SECRET_KEY, (err, userPayload) => {
        if (err) return res.sendStatus(403); 
        req.user = userPayload; 
        next(); 
    });
}

// --- 3. ЗАЩИЩЕННЫЙ МАРШРУТ (ПРИВЕТСТВИЕ) ---
app.get('/api/greeting', authenticateToken, (req, res) => {
    const userName = req.user.name;
    res.status(200).json({ 
        success: true,
        message: `Привет, ${userName}!`,
        userName: userName
    });
});


app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});