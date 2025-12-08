// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С POSTGRESQL И УЛУЧШЕННОЙ ОТЛАДКОЙ

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg'); 
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000; 
const SALT_ROUNDS = 10;

// !!! СЕКРЕТЫ ИЗ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ RENDER !!!
const SECRET_KEY = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL; 

if (!SECRET_KEY || !DATABASE_URL) {
    console.error("КРИТИЧЕСКАЯ ОШИБКА: Не установлен один из ключей: JWT_SECRET или DATABASE_URL.");
    process.exit(1); 
}

// --- ПОДКЛЮЧЕНИЕ К POSTGRESQL ---
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false 
    }
});

// Функция для создания таблиц (ОСТАВЛЕНО БЕЗ ИЗМЕНЕНИЙ)
async function createUsersTable() {
    try {
        const queryUsers = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                hashedPassword VARCHAR(100) NOT NULL,
                role VARCHAR(50) DEFAULT 'Студент' 
            );
        `;
        await pool.query(queryUsers);
        console.log('Таблица users успешно создана или уже существует.');

        const queryDocuments = `
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                template JSONB NOT NULL,
                student_email VARCHAR(100) NOT NULL,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                status VARCHAR(50) DEFAULT 'Ожидает заполнения', 
                submitted_data JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await pool.query(queryDocuments);
        console.log('Таблица documents успешно создана или уже существует.');


        const curatorCheck = await pool.query('SELECT 1 FROM users WHERE email = $1', ['curator@vuz.ru']);
        if (curatorCheck.rowCount === 0) {
            const password = '123456';
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS); 
            await pool.query(
                'INSERT INTO users (name, email, hashedPassword, role) VALUES ($1, $2, $3, $4)',
                ['Куратор Иван', 'curator@vuz.ru', hashedPassword, 'Куратор']
            );
            console.log('Тестовый Куратор (curator@vuz.ru) добавлен. Пароль: 123456');
        }

    } catch (err) {
        console.error('Ошибка создания таблиц:', err);
    }
}
createUsersTable();


// --- НАСТРОЙКА CORS и MIDDLEWARE ---
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


// --- MIDDLEWARE ПРОВЕРКИ JWT и РОЛИ ---
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

function isCurator(req, res, next) {
    if (req.user && req.user.role === 'Куратор') {
        next(); 
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Куратор." });
    }
}

// --- MIDDLEWARE ПРОВЕРКИ РОЛИ ПРЕПОДАВАТЕЛЯ ---
function isTeacher(req, res, next) {
    if (req.user && req.user.role === 'Преподаватель') {
        next(); 
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Преподаватель." });
    }
}


// --- 1. МАРШРУТ РЕГИСТРАЦИИ (БЕЗ ИЗМЕНЕНИЙ) ---
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    try {
        const existingUser = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
        if (existingUser.rowCount > 0) {
            return res.status(409).json({ success: false, message: 'Этот Email уже зарегистрирован.' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        await pool.query(
            'INSERT INTO users (name, email, hashedPassword, role) VALUES ($1, $2, $3, $4)',
            [name, email, hashedPassword, 'Студент'] 
        );
        
        res.status(201).json({ success: true, message: 'Регистрация успешна. Вы Студент.' });
    } catch (error) {
        console.error("Ошибка регистрации:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при регистрации.' });
    }
});

// --- 2. МАРШРУТ АВТОРИЗАЦИИ (БЕЗ ИЗМЕНЕНИЙ) ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await pool.query('SELECT id, name, role, email, hashedpassword FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) return res.status(401).json({ success: false, message: 'Неверные данные.' });

        const isPasswordValid = await bcrypt.compare(password, user.hashedpassword); 
        
        if (!isPasswordValid) return res.status(401).json({ success: false, message: 'Неверные данные.' });

        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role, email: user.email }, 
            SECRET_KEY, 
            { expiresIn: '1d' } 
        );

        return res.status(200).json({ success: true, token: token, role: user.role });
    } catch (error) {
        console.error("Ошибка входа:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при входе.' });
    }
});

// --- 3. ЗАЩИЩЕННЫЙ МАРШРУТ (ПРИВЕТСТВИЕ) (БЕЗ ИЗМЕНЕНИЙ) ---
app.get('/api/greeting', authenticateToken, (req, res) => {
    const userName = req.user.name;
    const userRole = req.user.role; 

    res.status(200).json({ 
        success: true,
        message: `Привет, ${userName}!`,
        userName: userName,
        userRole: userRole
    });
});

// --- 4. ЗАЩИЩЕННЫЙ МАРШРУТ (ИЗМЕНЕНИЕ РОЛИ) (БЕЗ ИЗМЕНЕНИЙ) ---
app.put('/api/users/role', authenticateToken, isCurator, async (req, res) => {
    const { email, newRole } = req.body;

    if (!['Студент', 'Преподаватель', 'Куратор'].includes(newRole)) {
        return res.status(400).json({ success: false, message: "Неверная целевая роль." });
    }

    try {
        const result = await pool.query(
            'UPDATE users SET role = $1 WHERE email = $2 RETURNING id',
            [newRole, email]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Пользователь с email ${email} не найден.` });
        }

        res.status(200).json({ 
            success: true, 
            message: `Роль пользователя ${email} успешно обновлена на ${newRole}.` 
        });
    } catch (error) {
        console.error("Ошибка при обновлении роли:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при обновлении роли." });
    }
});


// --- 5. МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ (БЕЗ ИЗМЕНЕНИЙ) ---
app.get('/api/users', authenticateToken, isCurator, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, email, role, hashedpassword FROM users ORDER BY id ASC');
        
        res.status(200).json({ 
            success: true, 
            users: result.rows
        });
    } catch (error) {
        console.error("Ошибка получения списка пользователей:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении данных." });
    }
});


// --- 6. МАРШРУТ: СОЗДАНИЕ НОВОГО ДОКУМЕНТА (ОБНОВЛЕНО ДЛЯ ОТЛАДКИ) ---
app.post('/api/documents/create', authenticateToken, isTeacher, async (req, res) => {
    const { title, studentEmail, template } = req.body;
    let teacherId = req.user.id; // Используем let для возможности изменения

    if (!title || !studentEmail || !template) {
        return res.status(400).json({ success: false, message: "Отсутствуют обязательные поля: title, studentEmail, template." });
    }
    
    // --- ИСПРАВЛЕНИЕ: ПРИВЕДЕНИЕ ID К ЧИСЛУ ---
    if (typeof teacherId === 'string') {
        teacherId = parseInt(teacherId, 10);
    }
    if (isNaN(teacherId)) {
         console.error("Ошибка аутентификации: teacherId не является числом:", req.user.id);
         return res.status(400).json({ success: false, message: "Ошибка аутентификации: ID преподавателя недействителен." });
    }
    
    // Проверка существования студента
    const studentCheck = await pool.query('SELECT 1 FROM users WHERE email = $1 AND role = $2', [studentEmail, 'Студент']);
    if (studentCheck.rowCount === 0) {
        return res.status(404).json({ success: false, message: `Студент с email ${studentEmail} не найден.` });
    }

    try {
        const result = await pool.query(
            'INSERT INTO documents (title, student_email, template, teacher_id) VALUES ($1, $2, $3, $4) RETURNING id',
            [title, studentEmail, template, teacherId]
        );

        res.status(201).json({ 
            success: true, 
            message: 'Документ успешно создан и отправлен студенту.',
            documentId: result.rows[0].id
        });
    } catch (error) {
        // --- УЛУЧШЕННОЕ ЛОГИРОВАНИЕ ОШИБКИ СЕРВЕРА ---
        console.error("Ошибка при создании документа (SQL/Server):", error.message); 
        console.error("Используемые данные:", { title, studentEmail, template: JSON.stringify(template).substring(0, 100) + '...', teacherId });
        res.status(500).json({ success: false, message: "Ошибка сервера при создании документа." });
    }
});


// --- 7. МАРШРУТ: ПОЛУЧЕНИЕ ДОКУМЕНТОВ ДЛЯ ЗАПОЛНЕНИЯ (БЕЗ ИЗМЕНЕНИЙ) ---
app.get('/api/documents/student', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Студент') {
        return res.status(403).json({ success: false, message: "Доступ разрешен только для Студентов." });
    }
    
    const studentEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            'SELECT id, title, template, status, submitted_data FROM documents WHERE student_email = $1 ORDER BY created_at DESC',
            [studentEmail]
        );
        
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows.filter(doc => doc.status === 'Ожидает заполнения') 
        });

    } catch (error) {
        console.error("Ошибка получения документов для студента:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});

// --- 8. МАРШРУТ: ОТПРАВКА ЗАПОЛНЕННОГО ДОКУМЕНТА (БЕЗ ИЗМЕНЕНИЙ) ---
app.put('/api/documents/submit/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Студент') {
        return res.status(403).json({ success: false, message: "Доступ разрешен только для Студентов." });
    }
    
    const documentId = req.params.id;
    const { filledData } = req.body;
    
    if (!filledData) {
         return res.status(400).json({ success: false, message: "Отсутствуют заполненные данные." });
    }
    
    const studentEmail = req.user.email;

    try {
        const result = await pool.query(
            'UPDATE documents SET status = $1, submitted_data = $2 WHERE id = $3 AND student_email = $4 RETURNING id',
            ['Заполнено', filledData, documentId, studentEmail]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или не предназначен для вас.` });
        }

        res.status(200).json({ 
            success: true, 
            message: `Документ "${documentId}" успешно заполнен и отправлен.` 
        });
    } catch (error) {
        console.error("Ошибка при отправке заполненного документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при отправке документа." });
    }
});


app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});