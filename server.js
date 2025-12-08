// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С ПОЛНЫМ ДОКУМЕНТООБОРОТОМ

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

// --- ШАБЛОНЫ ДОКУМЕНТОВ ---
const documentTemplates = {
    // 1. Заявление на Отпуск
    'Заявление на Отпуск': {
        parts: [
            { type: "text", content: "Я, Студент " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: ", прошу предоставить мне отпуск с " },
            { type: "input", name: "Дата_Начала", role: "Студент" },
            { type: "text", content: " по " },
            { type: "input", name: "Дата_Окончания", role: "Студент" },
            { type: "text", content: ". Приказ о согласовании №" },
            { type: "input", name: "Номер_Приказа_Ректора", role: "Преподаватель" }, // Заполняет Преподаватель
            { type: "text", content: "." }
        ]
    },
    // 2. Уведомление о Задолженности
    'Уведомление о Задолженности': {
        parts: [
            { type: "text", content: "Уважаемый Студент " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: "! У вас имеется задолженность по предмету " },
            { type: "input", name: "Название_Предмета", role: "Преподаватель" }, // Заполняет Преподаватель
            { type: "text", content: ". Текущий долг: " },
            { type: "input", name: "Тема_Долга", role: "Студент" },
            { type: "text", content: ". Крайний срок сдачи до " },
            { type: "input", name: "Крайний_Срок", role: "Преподаватель" }, // Заполняет Преподаватель
            { type: "text", content: "." }
        ]
    },
    // 3. Запрос на Смену Руководителя
    'Запрос на Смену Руководителя': {
        parts: [
            { type: "text", content: "Прошу разрешить мне, студенту " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: ", сменить научного руководителя дипломного проекта с " },
            { type: "input", name: "Текущий_Руководитель", role: "Преподаватель" }, // Заполняет Преподаватель
            { type: "text", content: " на " },
            { type: "input", name: "Новый_Руководитель", role: "Преподаватель" }, // Заполняет Преподаватель
            { type: "text", content: ". Причина, указанная студентом: " },
            { type: "input", name: "Причина_Смены", role: "Студент" },
            { type: "text", content: "." }
        ]
    }
};

// Функция для создания таблиц 
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

        // ТАБЛИЦА DOCUMENTS 
        const queryDocuments = `
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                template JSONB NOT NULL,
                student_email VARCHAR(100) NOT NULL,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                status VARCHAR(50) DEFAULT 'Ожидает заполнения', 
                submitted_data JSONB, // Хранит заполненные данные
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await pool.query(queryDocuments);
        console.log('Таблица documents успешно создана или уже существует.');


        // Добавление тестового Куратора, если он не существует (Пароль: 123456)
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
    'https://vuz-portal-frontend.onrender.com', 
    
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

function isTeacher(req, res, next) {
    if (req.user && req.user.role === 'Преподаватель') {
        next(); 
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Преподаватель." });
    }
}


// --- 1. Маршрут: Регистрация ---
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

// --- 2. Маршрут: Вход ---
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

// --- 3. Маршрут: Приветствие ---
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

// --- 4. Маршрут: Изменение роли (Куратор) ---
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

// --- 5. Маршрут: Получение пользователей (Куратор) ---
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


// --- 6. Маршрут: Создание нового документа (Преподаватель) ---
app.post('/api/documents/create', authenticateToken, isTeacher, async (req, res) => {
    const { templateName, studentEmail, title, teacherData } = req.body; 

    const template = documentTemplates[templateName];
    if (!template) {
        return res.status(400).json({ success: false, message: `Шаблон с именем "${templateName}" не найден в коде сервера.` });
    }

    const finalTitle = title || templateName;
    const teacherId = req.user.id; 
    
    if (!studentEmail) {
        return res.status(400).json({ success: false, message: "Отсутствует Email студента." });
    }
    let finalTeacherId = typeof teacherId === 'string' ? parseInt(teacherId, 10) : teacherId;
    if (isNaN(finalTeacherId)) {
         return res.status(400).json({ success: false, message: "Ошибка аутентификации: ID преподавателя недействителен." });
    }
    
    const studentCheck = await pool.query('SELECT 1 FROM users WHERE email = $1 AND role = $2', [studentEmail, 'Студент']);
    if (studentCheck.rowCount === 0) {
        return res.status(404).json({ success: false, message: `Студент с email ${studentEmail} не найден.` });
    }

    try {
        const result = await pool.query(
            'INSERT INTO documents (title, student_email, template, teacher_id, submitted_data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [finalTitle, studentEmail, template, finalTeacherId, teacherData || {}] // Сохраняем заполненные Преподавателем данные
        );

        res.status(201).json({ 
            success: true, 
            message: `Документ "${finalTitle}" успешно создан и отправлен студенту.`,
            documentId: result.rows[0].id
        });
    } catch (error) {
        console.error("Ошибка при создании документа (SQL/Server):", error.message); 
        res.status(500).json({ success: false, message: "Ошибка сервера при создании документа." });
    }
});


// --- 7. Маршрут: Получение документов для заполнения (Студент) ---
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
        
        // Отправляем документы, которые ожидают заполнения ИЛИ отправлены на доработку
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows.filter(doc => doc.status === 'Ожидает заполнения' || doc.status === 'На доработку') 
        });

    } catch (error) {
        console.error("Ошибка получения документов для студента:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});


// --- 8. Маршрут: Отправка заполненного документа (Студент) ---
app.put('/api/documents/submit/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Студент') {
        return res.status(403).json({ success: false, message: "Доступ разрешен только для Студентов." });
    }
    
    const documentId = req.params.id;
    const { studentData } = req.body; 
    
    if (!studentData) {
         return res.status(400).json({ success: false, message: "Отсутствуют заполненные данные." });
    }
    
    const studentEmail = req.user.email;

    try {
        // 1. Получаем текущие данные (заполненные преподавателем/студентом)
        const currentDoc = await pool.query(
            'SELECT submitted_data FROM documents WHERE id = $1 AND student_email = $2',
            [documentId, studentEmail]
        );

        if (currentDoc.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или не предназначен для вас.` });
        }
        
        const existingData = currentDoc.rows[0].submitted_data || {};
        
        // 2. Объединяем старые и новые данные (новые данные студента перезаписывают старые)
        const finalSubmittedData = { ...existingData, ...studentData };
        
        // 3. Обновляем статус и данные
        // Статус меняется на 'Заполнено', независимо от того, был ли он 'Ожидает заполнения' или 'На доработку'
        const result = await pool.query(
            'UPDATE documents SET status = $1, submitted_data = $2 WHERE id = $3 AND student_email = $4 RETURNING id',
            ['Заполнено', finalSubmittedData, documentId, studentEmail]
        );


        res.status(200).json({ 
            success: true, 
            message: `Документ "${documentId}" успешно заполнен и отправлен на проверку.` 
        });
    } catch (error) {
        console.error("Ошибка при отправке заполненного документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при отправке документа." });
    }
});


// --- 9. Маршрут: Рассмотрение документа Преподавателем (ОДОБРЕНИЕ/ОТКАЗ) ---
app.put('/api/documents/review/:id', authenticateToken, isTeacher, async (req, res) => {
    const documentId = req.params.id;
    // action: 'REJECT' или 'APPROVE'
    const { action, documentNumber, documentDate, reason } = req.body; 
    const teacherId = req.user.id; 

    try {
        // 1. Проверяем документ
        const currentDoc = await pool.query(
            'SELECT submitted_data, status FROM documents WHERE id = $1 AND teacher_id = $2',
            [documentId, teacherId]
        );

        if (currentDoc.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или не принадлежит вам.` });
        }
        
        const currentStatus = currentDoc.rows[0].status;
        if (currentStatus !== 'Заполнено') {
            return res.status(400).json({ success: false, message: `Документ находится в статусе "${currentStatus}". Изменить можно только документ в статусе "Заполнено".` });
        }
        
        let newStatus;
        let finalDataUpdate = {};
        let successMessage;

        if (action === 'REJECT') {
            // Отправить на доработку
            newStatus = 'На доработку';
            // Добавляем причину в submitted_data, чтобы студент ее увидел
            finalDataUpdate = { review_reason: reason || 'Причина не указана.' };
            successMessage = `Документ ${documentId} отправлен студенту на доработку.`;

        } else if (action === 'APPROVE') {
            // Одобрить и отправить Куратору
            if (!documentNumber || !documentDate) {
                 return res.status(400).json({ success: false, message: "Для одобрения необходимо указать Номер документа и Дату регистрации." });
            }
            newStatus = 'Одобрено, Куратору';
            // Добавляем финальные данные к уже существующим
            finalDataUpdate = { documentNumber: documentNumber, documentDate: documentDate };
            successMessage = `Документ ${documentId} одобрен и отправлен Куратору.`;

        } else {
            return res.status(400).json({ success: false, message: "Неверное действие." });
        }
        
        // Объединяем финальные данные с существующими в submitted_data
        const existingData = currentDoc.rows[0].submitted_data || {};
        const mergedData = { ...existingData, ...finalDataUpdate };
        
        // Обновляем статус и данные
        await pool.query(
            'UPDATE documents SET status = $1, submitted_data = $2 WHERE id = $3',
            [newStatus, mergedData, documentId]
        );

        res.status(200).json({ success: true, message: successMessage });

    } catch (error) {
        console.error("Ошибка при рассмотрении документа преподавателем:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при рассмотрении документа." });
    }
});


// --- 10. Маршрут: Получение всех документов, созданных Преподавателем ---
app.get('/api/documents/teacher', authenticateToken, isTeacher, async (req, res) => {
    
    const teacherId = req.user.id; 

    try {
        // Получаем ВСЕ документы, созданные данным преподавателем (по teacher_id)
        const documentsResult = await pool.query(
            `SELECT id, title, student_email, template, status, submitted_data, created_at 
             FROM documents 
             WHERE teacher_id = $1 
             ORDER BY created_at DESC`,
            [teacherId]
        );
        
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows 
        });

    } catch (error) {
        console.error("Ошибка получения документов для преподавателя:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});

app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});