// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С ПОЛНЫМ ЦИКЛОМ ПРОВЕРКИ (Студент -> Преподаватель -> Куратор)

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

// --- ШАБЛОНЫ ДОКУМЕНТОВ (ОБНОВЛЕННЫЙ: Добавлено финальное поле Преподавателя в первом шаблоне) ---
const documentTemplates = {
    'Заявление на Отпуск': {
        parts: [
            { type: "text", content: "Я, Студент " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: ", прошу предоставить мне отпуск с " },
            { type: "input", name: "Дата_Начала", role: "Студент" },
            { type: "text", content: " по " },
            { type: "input", name: "Дата_Окончания", role: "Студент" },
            { type: "text", content: ". Приказ о согласовании №" },
            { type: "input", name: "Номер_Приказа_Ректора", role: "Преподаватель" }, 
            { type: "text", content: ". Примечание преподавателя: " }, 
            { type: "input", name: "Примечание_Преподавателя_Финальное", role: "Преподаватель" } // Добавлено поле, которое заполняется после студента
        ]
    },
    'Уведомление о Задолженности': {
        parts: [
            { type: "text", content: "Уважаемый Студент " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: "! У вас имеется задолженность по предмету " },
            { type: "input", name: "Название_Предмета", role: "Преподаватель" }, 
            { type: "text", content: ". Текущий долг: " },
            { type: "input", name: "Тема_Долга", role: "Студент" },
            { type: "text", content: ". Крайний срок сдачи до " },
            { type: "input", name: "Крайний_Срок", role: "Преподаватель" }, 
            { type: "text", content: "." }
        ]
    },
    'Запрос на Смену Руководителя': {
        parts: [
            { type: "text", content: "Прошу разрешить мне, студенту " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: ", сменить научного руководителя дипломного проекта с " },
            { type: "input", name: "Текущий_Руководитель", role: "Преподаватель" }, 
            { type: "text", content: " на " },
            { type: "input", name: "Новый_Руководитель", role: "Преподаватель" }, 
            { type: "text", content: ". Причина, указанная студентом: " },
            { type: "input", name: "Причина_Смены", role: "Студент" },
            { type: "text", content: "." }
        ]
    }
};

// Функция для создания таблиц (ОБНОВЛЕНА: добавлено teacher_comment)
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
        
        const queryDocuments = `
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                template JSONB NOT NULL,
                student_email VARCHAR(100) NOT NULL,
                teacher_id INTEGER NOT NULL REFERENCES users(id),
                status VARCHAR(50) DEFAULT 'Ожидает заполнения', 
                submitted_data JSONB, 
                teacher_comment TEXT, -- НОВОЕ ПОЛЕ ДЛЯ КОММЕНТАРИЯ ПРЕПОДАВАТЕЛЯ
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await pool.query(queryDocuments);
        
        // Попытка добавить поле, если оно не существует (если таблица уже была создана ранее)
        // В реальном проекте требуется более сложная миграция, но для примера этого достаточно
        try {
            await pool.query("ALTER TABLE documents ADD COLUMN IF NOT EXISTS teacher_comment TEXT");
        } catch(err) {
            // Если ALTER TABLE завершится ошибкой (например, в некоторых старых версиях PostgreSQL без IF NOT EXISTS)
            console.warn("Предупреждение: Не удалось выполнить ALTER TABLE для teacher_comment.");
        }


        const curatorCheck = await pool.query('SELECT 1 FROM users WHERE email = $1', ['curator@vuz.ru']);
        if (curatorCheck.rowCount === 0) {
            const password = '123456';
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS); 
            await pool.query(
                'INSERT INTO users (name, email, hashedPassword, role) VALUES ($1, $2, $3, $4)',
                ['Куратор Иван', 'curator@vuz.ru', hashedPassword, 'Куратор']
            );
        }
    } catch (err) {
        console.error('Ошибка создания таблиц:', err);
    }
}
createUsersTable();


// --- НАСТРОЙКА CORS и MIDDLEWARE (Без изменений) ---
const allowedOrigins = [
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


// --- MIDDLEWARE ПРОВЕРКИ JWT и РОЛИ (Без изменений) ---
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

function isTeacherOrCurator(req, res, next) {
    if (req.user && (req.user.role === 'Преподаватель' || req.user.role === 'Куратор')) {
        next(); 
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Преподаватель или Куратор." });
    }
}

// --- 1-6. Маршруты Аутентификации, Управления Ролями и Создания Документа (Без изменений) ---

app.post('/api/register', async (req, res) => {
// ... (Register logic)
// ...
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

app.post('/api/login', async (req, res) => {
// ... (Login logic)
// ...
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

app.get('/api/greeting', authenticateToken, (req, res) => {
// ... (Greeting logic)
// ...
    const userName = req.user.name;
    const userRole = req.user.role; 

    res.status(200).json({ 
        success: true,
        userName: userName,
        userRole: userRole
    });
});

app.put('/api/users/role', authenticateToken, isCurator, async (req, res) => {
// ... (Role update logic)
// ...
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

app.get('/api/users', authenticateToken, isCurator, async (req, res) => {
// ... (Get all users logic)
// ...
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


// --- 6. МАРШРУТ: СОЗДАНИЕ НОВОГО ДОКУМЕНТА (Без изменений) ---
app.post('/api/documents/create', authenticateToken, isTeacher, async (req, res) => {
// ... (Document creation logic)
// ...
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
            'INSERT INTO documents (title, student_email, template, teacher_id, submitted_data, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [finalTitle, studentEmail, template, finalTeacherId, teacherData || {}, 'Ожидает заполнения'] 
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


// --- 7. МАРШРУТ: ПОЛУЧЕНИЕ ДОКУМЕНТОВ ДЛЯ ЗАПОЛНЕНИЯ (СТУДЕНТ) (ОБНОВЛЕН) ---
app.get('/api/documents/student', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Студент') {
        return res.status(403).json({ success: false, message: "Доступ разрешен только для Студентов." });
    }
    
    const studentEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            // Студент видит документы, которые нужно заполнить ИЛИ те, которые отправили на доработку.
            'SELECT id, title, template, status, submitted_data, teacher_comment FROM documents WHERE student_email = $1 AND (status = $2 OR status = $3) ORDER BY created_at DESC',
            [studentEmail, 'Ожидает заполнения', 'Отправлено на доработку']
        );
        
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows
        });

    } catch (error) {
        console.error("Ошибка получения документов для студента:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});


// --- 8. МАРШРУТ: ОТПРАВКА ЗАПОЛНЕННОГО ДОКУМЕНТА (СТУДЕНТ) (ОБНОВЛЕН) ---
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
        const currentDoc = await pool.query(
            'SELECT submitted_data FROM documents WHERE id = $1 AND student_email = $2',
            [documentId, studentEmail]
        );

        if (currentDoc.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или не предназначен для вас.` });
        }
        
        const existingData = currentDoc.rows[0].submitted_data || {};
        
        const finalSubmittedData = { ...existingData, ...studentData };
        
        const result = await pool.query(
            // Новый статус: Ожидает проверки преподавателем
            'UPDATE documents SET status = $1, submitted_data = $2, teacher_comment = NULL WHERE id = $3 AND student_email = $4 RETURNING id',
            ['Ожидает проверки преподавателем', finalSubmittedData, documentId, studentEmail]
        );


        res.status(200).json({ 
            success: true, 
            message: `Документ "${documentId}" успешно отправлен на проверку преподавателю.` 
        });
    } catch (error) {
        console.error("Ошибка при отправке заполненного документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при отправке документа." });
    }
});


// --- 9. МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ДОКУМЕНТОВ, СОЗДАННЫХ ПРЕПОДАВАТЕЛЕМ (ОБНОВЛЕН: добавлен teacher_comment) ---
app.get('/api/documents/teacher', authenticateToken, isTeacher, async (req, res) => {
    
    const teacherId = req.user.id; 

    try {
        const documentsResult = await pool.query(
            `SELECT id, title, student_email, template, status, submitted_data, created_at, teacher_comment 
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

// --- 12. НОВЫЙ МАРШРУТ: ДЕЙСТВИЯ ПРЕПОДАВАТЕЛЯ (ОТКЛОНЕНИЕ/УТВЕРЖДЕНИЕ) ---
app.put('/api/documents/teacher/action/:id', authenticateToken, isTeacher, async (req, res) => {
    const documentId = req.params.id;
    const teacherId = req.user.id;
    const { action, teacherData, comment } = req.body; // action: 'approve' или 'reject'
    
    if (!['approve', 'reject'].includes(action)) {
        return res.status(400).json({ success: false, message: "Неверное действие. Допустимо 'approve' или 'reject'." });
    }

    try {
        const docResult = await pool.query(
            'SELECT submitted_data, status FROM documents WHERE id = $1 AND teacher_id = $2',
            [documentId, teacherId]
        );

        if (docResult.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или недоступен для вас.` });
        }
        
        // Объединяем существующие данные с данными, заполненными преподавателем на этом шаге
        const currentData = docResult.rows[0].submitted_data || {};
        const finalData = { ...currentData, ...(teacherData || {}) };
        
        let newStatus;
        let updateQuery;
        let updateParams;
        let successMessage;

        if (action === 'reject') {
            if (!comment || comment.trim() === '') {
                 return res.status(400).json({ success: false, message: "Необходим комментарий для отправки на доработку." });
            }
            newStatus = 'Отправлено на доработку';
            // Обновляем статус и добавляем комментарий
            updateQuery = 'UPDATE documents SET status = $1, teacher_comment = $2 WHERE id = $3 RETURNING id';
            updateParams = [newStatus, comment.trim(), documentId];
            successMessage = `Документ ${documentId} отправлен студенту на доработку.`;

        } else if (action === 'approve') {
            newStatus = 'Готов к утверждению куратором';
            // Обновляем статус, сохраняем финальные данные и очищаем комментарий
            updateQuery = 'UPDATE documents SET status = $1, submitted_data = $2, teacher_comment = NULL WHERE id = $3 RETURNING id';
            updateParams = [newStatus, finalData, documentId];
            successMessage = `Документ ${documentId} отправлен Куратору на утверждение.`;
        }

        await pool.query(updateQuery, updateParams);

        res.status(200).json({ success: true, message: successMessage, newStatus: newStatus });
        
    } catch (error) {
        console.error("Ошибка при действии преподавателя:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при выполнении действия." });
    }
});


// --- 10. МАРШРУТ: СКАЧИВАНИЕ ФИНАЛЬНОГО ДОКУМЕНТА (КУРАТОР/ПРЕПОДАВАТЕЛЬ) (ОБНОВЛЕН) ---
app.get('/api/documents/download/:id', authenticateToken, isTeacherOrCurator, async (req, res) => {
    const documentId = req.params.id;
    const isCurator = req.user.role === 'Куратор';
    const teacherId = req.user.id;

    try {
        let query = `SELECT d.title, d.submitted_data, d.template
                     FROM documents d
                     WHERE d.id = $1 AND d.status IN ('Готов к утверждению куратором', 'Утверждено куратором')`;
        let params = [documentId];

        // Если это не Куратор, добавляем проверку на принадлежность документа
        if (!isCurator) {
            query += ` AND d.teacher_id = $2`;
            params.push(teacherId);
        }

        const docResult = await pool.query(query, params);
        const doc = docResult.rows[0];

        if (!doc) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден, не утвержден или недоступен для вас.` });
        }

        const submittedData = doc.submitted_data || {};
        const templateParts = doc.template.parts || [];
        
        let fileContent = `--- Документ: ${doc.title} (ID: ${documentId}) ---\n\n`;
        
        // Форматируем контент
        templateParts.forEach(part => {
            if (part.type === 'text') {
                fileContent += part.content.trim() + ' ';
            } else if (part.type === 'input') {
                const value = submittedData[part.name] || `[НЕ ЗАПОЛНЕНО: ${part.name} (${part.role})]`;
                fileContent += `${value} `;
            }
        });
        
        fileContent += `\n\n--------------------------------------------\n`;
        fileContent += `Дата формирования: ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`;

        const filename = `${doc.title.replace(/\s/g, '_')}_ID${documentId}.txt`;
        
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.send(fileContent);

    } catch (error) {
        console.error("Ошибка при скачивании документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при скачивании документа." });
    }
});

// --- 11. МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ДОКУМЕНТОВ (КУРАТОР) (Без изменений) ---
app.get('/api/documents/all', authenticateToken, isCurator, async (req, res) => {
    try {
        const documentsResult = await pool.query(
            `SELECT 
                d.id, 
                d.title, 
                d.student_email, 
                d.status, 
                d.created_at,
                u.name AS teacher_name
             FROM documents d
             JOIN users u ON d.teacher_id = u.id
             ORDER BY d.created_at DESC`
        );
        
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows 
        });

    } catch (error) {
        console.error("Ошибка получения всех документов для куратора:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});


app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});