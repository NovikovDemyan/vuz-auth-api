// auth_api/server.js

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config(); 

const app = express();
const port = process.env.PORT || 3000; 
const SALT_ROUNDS = 10;
const SECRET_KEY = process.env.JWT_SECRET; 

if (!SECRET_KEY) {
    console.error("КРИТИЧЕСКАЯ ОШИБКА: JWT_SECRET не установлен.");
    process.exit(1); 
}

// --- УПРОЩЕННАЯ "БД" В ПАМЯТИ ---
let nextUserId = 3; // Начинаем с 3, так как 1 и 2 зарезервированы
const usersDB = [
    // Пользователь 1: Куратор (для тестирования изменения ролей)
    { id: 1, name: 'Куратор Иван', email: 'curator@vuz.ru', role: 'Куратор', hashedPassword: '$2b$10$wTf2A2jD7zQfG/J0yK8X9Oa5iB3C2D1E0F9G8H7I6J5K4L3M2N1O0' }, 
    // Пользователь 2: Преподаватель
    { id: 2, name: 'Преподаватель Елена', email: 'teacher@vuz.ru', role: 'Преподаватель', hashedPassword: '$2b$10$wTf2A2jD7zQfG/J0yK8X9Oa5iB3C2D1E0F9G8H7I6J5K4L3M2N1O0' }
]; // Пароль для обоих: '123456'

// --- НАСТРОЙКА CORS ---
const allowedOrigins = [
    // !!! ДОЛЖЕН БЫТЬ ТОЧНО ЭТОТ АДРЕС ИЗ КОНСОЛИ !!!
    'https://fanciful-gingersnap-d87b1c.netlify.app', 
    
    'http://localhost:3000', 
    'http://localhost:5500', 
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) { 
            callback(null, true);
        } else {
            callback(new Error('CORS Policy Blocked'));
        }
    }
};

app.use(cors(corsOptions)); 
app.use(express.json()); 


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

// --- MIDDLEWARE ПРОВЕРКИ РОЛИ "Куратор" ---
function isCurator(req, res, next) {
    // Проверяем, что токен был успешно декодирован и содержит роль "Куратор"
    if (req.user && req.user.role === 'Куратор') {
        next(); // Куратор может продолжать
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Куратор." });
    }
}


// --- 1. МАРШРУТ РЕГИСТРАЦИИ ---
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (usersDB.find(u => u.email === email)) {
        return res.status(409).json({ success: false, message: 'Этот Email уже зарегистрирован.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = { 
            id: nextUserId++, 
            name, 
            email, 
            hashedPassword,
            role: 'Студент' // !!! НОВАЯ ЛОГИКА: РОЛЬ ПО УМОЛЧАНИЮ !!!
        };
        usersDB.push(newUser);
        res.status(201).json({ success: true, message: 'Регистрация успешна. Вы Студент.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Ошибка сервера при регистрации.' });
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
            { id: user.id, name: user.name, role: user.role }, // !!! НОВАЯ ЛОГИКА: ДОБАВЛЕНИЕ РОЛИ В ТОКЕН !!!
            SECRET_KEY, 
            { expiresIn: '1d' } 
        );

        return res.status(200).json({ success: true, token: token, role: user.role });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Ошибка сервера при входе.' });
    }
});

// --- 3. ЗАЩИЩЕННЫЙ МАРШРУТ (ПРИВЕТСТВИЕ) ---
app.get('/api/greeting', authenticateToken, (req, res) => {
    // В req.user теперь есть поля name и role
    const userName = req.user.name;
    const userRole = req.user.role; 

    res.status(200).json({ 
        success: true,
        message: `Привет, ${userName}!`,
        userName: userName,
        userRole: userRole
    });
});

// --- 4. ЗАЩИЩЕННЫЙ МАРШРУТ (ИЗМЕНЕНИЕ РОЛИ) ---
app.put('/api/users/role', authenticateToken, isCurator, (req, res) => {
    const { email, newRole } = req.body;

    if (!['Студент', 'Преподаватель', 'Куратор'].includes(newRole)) {
        return res.status(400).json({ success: false, message: "Неверная целевая роль." });
    }

    const targetUser = usersDB.find(u => u.email === email);

    if (!targetUser) {
        return res.status(404).json({ success: false, message: `Пользователь с email ${email} не найден.` });
    }

    // Обновляем роль
    targetUser.role = newRole;

    res.status(200).json({ 
        success: true, 
        message: `Роль пользователя ${email} успешно обновлена на ${newRole}.` 
    });
});

app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});