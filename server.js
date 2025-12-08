// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С ИСПРАВЛЕННОЙ СИНХРОНИЗАЦИЕЙ ЗАПУСКА

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors'); 
require('dotenv').config(); 

const app = express();
const port = process.env.PORT || 3000;
const SALT_ROUNDS = 10;


// --- 1. НАСТРОЙКА БАЗЫ ДАННЫХ И СЕКРЕТОВ ---

// !!! ВАЖНО: Убедитесь, что ваш DATABASE_URL установлен в Render или в .env !!!
const DATABASE_URL = process.env.DATABASE_URL; 
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SECURE_DEFAULT_SECRET_KEY'; 

if (!DATABASE_URL) {
    console.error("КРИТИЧЕСКАЯ ОШИБКА: Переменная DATABASE_URL не установлена.");
    // В отличие от предыдущей версии, здесь мы позволим процессу завершиться, 
    // чтобы Render корректно пометил сервис как нерабочий, если нет DB.
    process.exit(1); 
}

// Конфигурация для подключения к PostgreSQL (с SSL для Render)
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Требуется для Render
    }
});


// --- 2. НАСТРОЙКА CORS и MIDDLEWARE ---

// УПРОЩЕННЫЙ CORS (разрешает все для простоты развертывания)
app.use(cors({
    origin: '*', // Разрешаем доступ со всех доменов
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
}));

app.use(express.json()); 


// --- 3. ФУНКЦИИ ИНИЦИАЛИЗАЦИИ БД ---

// 3.1. Создание таблицы пользователей
async function createUsersTable() {
    try {
        const queryText = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(100) NOT NULL,
                role VARCHAR(50) NOT NULL,
                full_name VARCHAR(100)
            );
        `;
        await pool.query(queryText);
        console.log('Таблица users успешно создана или уже существует.');
    } catch (err) {
        console.error('КРИТИЧЕСКАЯ ОШИБКА: Ошибка создания таблицы users (проверьте DATABASE_URL):', err.message);
        throw err; // Перебрасываем ошибку, чтобы остановить запуск сервера
    }
}

// 3.2. Создание таблицы документов
async function createDocumentsTable() {
    try {
        const queryText = `
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                templateContent TEXT NOT NULL,
                targetStudentEmail VARCHAR(100) NOT NULL,
                currentContent TEXT,
                status VARCHAR(50) DEFAULT 'sent', 
                assignedBy VARCHAR(100) NOT NULL,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await pool.query(queryText);
        console.log('Таблица documents успешно создана или уже существует.');
    } catch (err) {
        console.error('КРИТИЧЕСКАЯ ОШИБКА: Ошибка создания таблицы documents:', err.message);
        throw err; // Перебрасываем ошибку
    }
}

// 3.3. Создание Куратора по умолчанию и тестовых аккаунтов
async function createDefaultAdmin() {
    const defaultEmail = 'admin@vuz.ru';
    const defaultPassword = 'admin';

    try {
        const check = await pool.query('SELECT * FROM users WHERE email = $1', [defaultEmail]);
        if (check.rows.length === 0) {
            const hashedPassword = await bcrypt.hash(defaultPassword, SALT_ROUNDS);
            await pool.query(
                'INSERT INTO users (email, password_hash, role, full_name) VALUES ($1, $2, $3, $4)',
                [defaultEmail, hashedPassword, 'Куратор', 'Главный Куратор']
            );
            
            const studentPass = await bcrypt.hash('123456', SALT_ROUNDS);
            await pool.query('INSERT INTO users (email, password_hash, role, full_name) VALUES ($1, $2, $3, $4)', ['student@vuz.ru', studentPass, 'Студент', 'Иванов Иван']);
            const teacherPass = await bcrypt.hash('123456', SALT_ROUNDS);
            await pool.query('INSERT INTO users (email, password_hash, role, full_name) VALUES ($1, $2, $3, $4)', ['teacher@vuz.ru', teacherPass, 'Преподаватель', 'Петров Пётр']);

            console.log(`Тестовые аккаунты созданы (Куратор: ${defaultEmail}/admin, Студент/Преподаватель: 123456)`);
        }
    } catch (err) {
        console.error('Ошибка создания тестовых пользователей:', err);
    }
}

// --- 3.4. Функция инициализации и запуска (НОВОЕ) ---
async function initializeApp() {
    try {
        // Ожидаем завершения всех DB операций перед запуском сервера
        await createUsersTable();
        await createDocumentsTable(); 
        await createDefaultAdmin(); 
        
        // Запуск сервера только после успешной инициализации DB
        app.listen(port, () => {
            console.log(`Сервер API запущен на порту ${port}`);
        });
    } catch (error) {
        console.error("СЕРВЕР НЕ БЫЛ ЗАПУЩЕН: Критическая ошибка инициализации (проверьте DB):", error.message);
        process.exit(1); // Выход, если DB недоступна
    }
}

// Вызов функции инициализации при старте
initializeApp();


// --- 4. MIDDLEWARE (Проверка ролей) ---

// 4.1. Проверка JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); 

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); 
        req.user = user;
        next();
    });
}

// 4.2. Проверка роли: Преподаватель или Куратор
function isTeacherOrCurator(req, res, next) {
    if (req.user && (req.user.role === 'Преподаватель' || req.user.role === 'Куратор')) {
        next(); 
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Преподаватель или Куратор." });
    }
}


// --- 5. МАРШРУТЫ АВТОРИЗАЦИИ/РЕГИСТРАЦИИ ---

// 5.1. Регистрация
app.post('/register', async (req, res) => {
    const { email, password, role, full_name } = req.body;
    
    const allowedRoles = ['Студент', 'Преподаватель', 'Куратор'];
    if (!allowedRoles.includes(role)) {
        return res.status(400).json({ success: false, message: "Некорректная роль." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, role, full_name) VALUES ($1, $2, $3, $4) RETURNING email, role, full_name',
            [email, hashedPassword, role, full_name]
        );
        res.status(201).json({ success: true, message: 'Пользователь успешно зарегистрирован.', user: result.rows[0] });
    } catch (error) {
        if (error.code === '23505') { 
            return res.status(409).json({ success: false, message: 'Пользователь с таким Email уже существует.' });
        }
        console.error("Ошибка регистрации:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при регистрации.' });
    }
});

// 5.2. Логин
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Неверный Email или пароль.' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(401).json({ success: false, message: 'Неверный Email или пароль.' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({ success: true, token, user: { email: user.email, role: user.role, full_name: user.full_name } });
    } catch (error) {
        // Это сообщение будет возвращено, если DB недоступна, но теперь мы уверены,
        // что сервер запущен только при доступности DB.
        console.error("Ошибка логина:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при авторизации.' });
    }
});

// 5.3. Получение профиля (защищенный маршрут)
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});


// --- 6. МАРШРУТЫ УПРАВЛЕНИЯ ДОКУМЕНТАМИ ---

// 6.1. СОЗДАНИЕ ЗАДАНИЯ (Преподаватель/Куратор)
app.post('/api/documents/create', authenticateToken, isTeacherOrCurator, async (req, res) => {
    const { title, templateContent, targetStudentEmail } = req.body;
    const assignedBy = req.user.email; 

    if (!title || !templateContent || !targetStudentEmail) {
        return res.status(400).json({ success: false, message: "Необходимо указать название, шаблон и Email студента." });
    }

    try {
        const studentCheck = await pool.query('SELECT email FROM users WHERE email = $1 AND role = $2', [targetStudentEmail, 'Студент']);
        if (studentCheck.rowCount === 0) {
             return res.status(404).json({ success: false, message: `Студент с email ${targetStudentEmail} не найден.` });
        }
        
        const result = await pool.query(
            'INSERT INTO documents (title, templateContent, targetStudentEmail, currentContent, assignedBy, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [title, templateContent, targetStudentEmail, templateContent, assignedBy, 'sent']
        );
        res.status(201).json({ success: true, message: 'Задание успешно отправлено студенту.', document: result.rows[0] });
    } catch (error) {
        console.error("Ошибка при создании документа:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при создании документа.' });
    }
});


// 6.2. ПОЛУЧЕНИЕ СПИСКА ЗАДАНИЙ (для Студента или Преподавателя)
app.get('/api/documents', authenticateToken, async (req, res) => {
    const userRole = req.user.role;
    const userEmail = req.user.email;
    let queryText;
    let queryParams;

    if (userRole === 'Студент') {
        queryText = 'SELECT id, title, status, assignedBy, createdAt FROM documents WHERE targetStudentEmail = $1 ORDER BY createdAt DESC';
        queryParams = [userEmail];
    } else if (userRole === 'Преподаватель' || userRole === 'Куратор') {
        queryText = 'SELECT id, title, status, targetStudentEmail, assignedBy, createdAt FROM documents WHERE assignedBy = $1 ORDER BY createdAt DESC';
        queryParams = [userEmail];
    } else {
        return res.status(403).json({ success: false, message: "Ваша роль не имеет доступа к документам." });
    }

    try {
        const result = await pool.query(queryText, queryParams);
        res.status(200).json({ success: true, documents: result.rows });
    } catch (error) {
        console.error("Ошибка при получении списка документов:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при получении списка документов.' });
    }
});


// 6.3. ПОЛУЧЕНИЕ КОНКРЕТНОГО ДОКУМЕНТА (для заполнения/просмотра)
app.get('/api/documents/:id', authenticateToken, async (req, res) => {
    const docId = req.params.id;
    const userEmail = req.user.email;

    try {
        const result = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND (targetStudentEmail = $2 OR assignedBy = $2)',
            [docId, userEmail]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'Документ не найден или у вас нет доступа.' });
        }

        res.status(200).json({ success: true, document: result.rows[0] });
    } catch (error) {
        console.error("Ошибка при получении документа по ID:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера.' });
    }
});


// 6.4. СОХРАНЕНИЕ / ОБНОВЛЕНИЕ ДОКУМЕНТА (ТОЛЬКО ДЛЯ СТУДЕНТА)
app.put('/api/documents/:id', authenticateToken, async (req, res) => {
    const docId = req.params.id;
    const { content, status } = req.body; 
    const userRole = req.user.role;
    const userEmail = req.user.email;

    if (userRole !== 'Студент') {
        return res.status(403).json({ success: false, message: "Только Студент может заполнять документы." });
    }

    const allowedStatuses = ['in_progress', 'completed'];
    if (!content || !allowedStatuses.includes(status)) {
        return res.status(400).json({ success: false, message: "Необходимо указать содержимое и корректный статус." });
    }

    try {
        const checkResult = await pool.query(
            'SELECT targetStudentEmail FROM documents WHERE id = $1',
            [docId]
        );
        if (checkResult.rowCount === 0 || checkResult.rows[0].targetStudentEmail !== userEmail) {
            return res.status(403).json({ success: false, message: 'Вы не являетесь целевым студентом для этого документа.' });
        }
        
        const updateResult = await pool.query(
            'UPDATE documents SET currentContent = $1, status = $2 WHERE id = $3 RETURNING *',
            [content, status, docId]
        );

        res.status(200).json({ success: true, message: `Документ обновлен. Новый статус: ${status}`, document: updateResult.rows[0] });

    } catch (error) {
        console.error("Ошибка при обновлении документа:", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера при обновлении документа.' });
    }
});