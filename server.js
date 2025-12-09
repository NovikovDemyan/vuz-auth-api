// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С РЕЦЕНЗИЕЙ ПРЕПОДАВАТЕЛЯ И УТВЕРЖДЕНИЕМ КУРАТОРА

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

// --- ПОДКЛЮЧЕНИЕ К POSTGRESQL ---\
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false 
    }
});

// --- ШАБЛОНЫ ДОКУМЕНТОВ ---\
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
            { type: "text", content: "." }
        ],
        requiredRoles: ['Преподаватель']
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
        ],
        requiredRoles: ['Преподаватель']
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
        ],
        requiredRoles: ['Преподаватель']
    }
};

// --- ИНИЦИАЛИЗАЦИЯ ТАБЛИЦЫ ДОКУМЕНТОВ ---
async function initializeDb() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                hashedpassword VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'Студент'
            );
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                template_name VARCHAR(255) NOT NULL,
                teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                status VARCHAR(50) DEFAULT 'Ожидает заполнения',
                submitted_data JSONB DEFAULT '{}'
            );
        `);
        // Создание тестовых пользователей, если их нет
        const testUsers = [
            { name: 'Куратор ВУЗа', email: 'curator@vuz.ru', role: 'Куратор', password: '123456' },
            { name: 'Преподаватель 1', email: 'teacher@vuz.ru', role: 'Преподаватель', password: '123456' },
            { name: 'Студент 1', email: 'student@vuz.ru', role: 'Студент', password: '123456' }
        ];

        for (const user of testUsers) {
            const result = await pool.query('SELECT * FROM users WHERE email = $1', [user.email]);
            if (result.rows.length === 0) {
                const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
                await pool.query(
                    'INSERT INTO users (name, email, hashedpassword, role) VALUES ($1, $2, $3, $4)',
                    [user.name, user.email, hashedPassword, user.role]
                );
                console.log(`Создан тестовый пользователь: ${user.email}`);
            }
        }
        
        console.log("База данных успешно инициализирована.");
    } catch (err) {
        console.error("Ошибка инициализации базы данных:", err);
    }
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// Middleware для проверки JWT токена и извлечения данных пользователя
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: "Необходима авторизация." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Недействительный или просроченный токен." });
        req.user = user;
        next();
    });
};

// Middleware для проверки роли
const checkRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ success: false, message: "Недостаточно прав для выполнения операции." });
    }
    next();
};

// --- АУТЕНТИФИКАЦИЯ И РЕГИСТРАЦИЯ ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        const result = await pool.query(
            'INSERT INTO users (name, email, hashedpassword) VALUES ($1, $2, $3) RETURNING id, name, role',
            [name, email, hashedPassword]
        );

        res.json({ success: true, message: "Пользователь успешно зарегистрирован как Студент.", user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(400).json({ success: false, message: "Пользователь с таким Email уже существует." });
        }
        console.error("Ошибка регистрации:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при регистрации." });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ success: false, message: "Неверный Email или пароль." });
        }

        const match = await bcrypt.compare(password, user.hashedpassword);
        if (!match) {
            return res.status(400).json({ success: false, message: "Неверный Email или пароль." });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name }, 
            SECRET_KEY, 
            { expiresIn: '24h' }
        );

        res.json({ success: true, message: "Вход выполнен успешно.", token, role: user.role });

    } catch (err) {
        console.error("Ошибка входа:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при входе." });
    }
});

app.get('/api/greeting', authenticateToken, (req, res) => {
    res.json({ 
        success: true, 
        message: `Привет, ${req.user.name}!`, 
        userName: req.user.name,
        userRole: req.user.role
    });
});

// --- УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ (КУРАТОР) ---
app.get('/api/users', authenticateToken, checkRole(['Куратор']), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, email, role, hashedpassword FROM users ORDER BY id');
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error("Ошибка при получении списка пользователей:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении данных пользователей." });
    }
});

app.put('/api/users/role', authenticateToken, checkRole(['Куратор']), async (req, res) => {
    try {
        const { email, newRole } = req.body;
        if (!['Студент', 'Преподаватель', 'Куратор'].includes(newRole)) {
            return res.status(400).json({ success: false, message: "Недопустимая роль." });
        }

        const result = await pool.query(
            'UPDATE users SET role = $1 WHERE email = $2 RETURNING id, name, role',
            [newRole, email]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Пользователь с таким Email не найден." });
        }

        res.json({ success: true, message: `Роль пользователя ${email} успешно обновлена на ${newRole}.` });

    } catch (err) {
        console.error("Ошибка обновления роли:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при обновлении роли." });
    }
});

// --- API ДОКУМЕНТОВ: СОЗДАНИЕ (ПРЕПОДАВАТЕЛЬ) ---
app.post('/api/documents/create', authenticateToken, checkRole(['Преподаватель']), async (req, res) => {
    try {
        const { templateName, studentEmail, title, teacherData } = req.body;
        const teacherId = req.user.id;
        
        const template = documentTemplates[templateName];
        if (!template) {
            return res.status(400).json({ success: false, message: "Неизвестный шаблон документа." });
        }

        // 1. Найти ID студента
        const studentResult = await pool.query('SELECT id FROM users WHERE email = $1 AND role = $2', [studentEmail, 'Студент']);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: `Студент с email ${studentEmail} не найден.` });
        }
        const studentId = studentResult.rows[0].id;
        
        // 2. Вставить документ
        const documentTitle = title || templateName;
        const result = await pool.query(
            'INSERT INTO documents (title, template_name, teacher_id, student_id, submitted_data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [documentTitle, templateName, teacherId, studentId, teacherData]
        );

        res.json({ 
            success: true, 
            message: `Документ "${documentTitle}" успешно создан и отправлен студенту ${studentEmail}.`,
            documentId: result.rows[0].id
        });

    } catch (err) {
        console.error("Ошибка создания документа:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при создании документа." });
    }
});

// --- API ДОКУМЕНТОВ: ПРОСМОТР ДЛЯ СТУДЕНТА ---
app.get('/api/documents/student', authenticateToken, checkRole(['Студент']), async (req, res) => {
    try {
        const studentId = req.user.id;

        const result = await pool.query(
            'SELECT id, title, template_name, status, submitted_data FROM documents WHERE student_id = $1 ORDER BY id DESC', 
            [studentId]
        );

        const documents = result.rows.map(doc => ({
            ...doc,
            template: documentTemplates[doc.template_name]
        }));

        res.json({ success: true, documents });

    } catch (err) {
        console.error("Ошибка загрузки документов для студента:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при загрузке документов." });
    }
});

// --- API ДОКУМЕНТОВ: ОТПРАВКА СТУДЕНТОМ ---
app.put('/api/documents/submit/:docId', authenticateToken, checkRole(['Студент']), async (req, res) => {
    try {
        const { docId } = req.params;
        const studentId = req.user.id;
        const { studentData } = req.body;

        // 1. Проверить, что документ существует и принадлежит студенту
        const docResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND student_id = $2', 
            [docId, studentId]
        );
        const doc = docResult.rows[0];

        if (!doc) {
            return res.status(404).json({ success: false, message: "Документ не найден или не принадлежит вам." });
        }
        
        if (doc.status !== 'Ожидает заполнения') {
             return res.status(400).json({ success: false, message: `Документ уже не находится в статусе "Ожидает заполнения". Текущий статус: ${doc.status}` });
        }

        // 2. Объединить новые данные с существующими (данные преподавателя)
        const newSubmittedData = { ...doc.submitted_data, ...studentData };
        
        // 3. Обновить статус и данные
        await pool.query(
            'UPDATE documents SET submitted_data = $1, status = $2 WHERE id = $3',
            [newSubmittedData, 'Заполнено', docId]
        );

        res.json({ success: true, message: `Документ "${doc.title}" успешно заполнен и отправлен на рецензию преподавателю.` });

    } catch (err) {
        console.error("Ошибка отправки документа студентом:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при отправке документа." });
    }
});

// --- API ДОКУМЕНТОВ: ПРОСМОТР ДЛЯ ПРЕПОДАВАТЕЛЯ ---
app.get('/api/documents/teacher', authenticateToken, checkRole(['Преподаватель']), async (req, res) => {
    try {
        const teacherId = req.user.id;

        const result = await pool.query(
            'SELECT d.id, d.title, d.template_name, d.status, d.submitted_data, u.email as student_email FROM documents d JOIN users u ON d.student_id = u.id WHERE d.teacher_id = $1 ORDER BY d.id DESC', 
            [teacherId]
        );

        const documents = result.rows.map(doc => ({
            ...doc,
            template: documentTemplates[doc.template_name]
        }));

        res.json({ success: true, documents });

    } catch (err) {
        console.error("Ошибка загрузки документов для преподавателя:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при загрузке документов." });
    }
});

// --- НОВЫЙ API ДОКУМЕНТОВ: РЕЦЕНЗИЯ ПРЕПОДАВАТЕЛЯ (ИЗМЕНЕНИЕ ДАННЫХ И СМЕНА СТАТУСА) ---
app.put('/api/documents/review/:docId', authenticateToken, checkRole(['Преподаватель']), async (req, res) => {
    try {
        const { docId } = req.params;
        const teacherId = req.user.id;
        const { reviewData } = req.body; 

        // 1. Проверить, что документ существует и принадлежит преподавателю
        const docResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1 AND teacher_id = $2', 
            [docId, teacherId]
        );
        const doc = docResult.rows[0];

        if (!doc) {
            return res.status(404).json({ success: false, message: "Документ не найден или не принадлежит вам." });
        }
        
        if (doc.status !== 'Заполнено') {
             return res.status(400).json({ success: false, message: `Документ должен быть в статусе "Заполнено" для рецензии. Текущий статус: ${doc.status}` });
        }

        // 2. Объединить рецензионные данные с существующими (перезаписывая поля Преподавателя)
        // Примечание: Фронтенд должен отправлять только поля, заполненные преподавателем.
        const newSubmittedData = { ...doc.submitted_data, ...reviewData };
        
        // 3. Обновить статус и данные
        await pool.query(
            'UPDATE documents SET submitted_data = $1, status = $2 WHERE id = $3',
            [newSubmittedData, 'Ожидает утверждения Куратором', docId]
        );

        res.json({ success: true, message: `Рецензия документа "${doc.title}" завершена. Отправлено Куратору на утверждение.` });

    } catch (err) {
        console.error("Ошибка рецензирования документа преподавателем:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при рецензировании документа." });
    }
});

// --- API ДОКУМЕНТОВ: ПРОСМОТР ДЛЯ КУРАТОРА ---
app.get('/api/documents/curator', authenticateToken, checkRole(['Куратор']), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT d.id, d.title, d.template_name, d.status, d.submitted_data, d.teacher_id, u.email as student_email FROM documents d JOIN users u ON d.student_id = u.id ORDER BY d.id DESC'
        );

        const documents = result.rows.map(doc => ({
            ...doc,
            template: documentTemplates[doc.template_name]
        }));

        res.json({ success: true, documents });

    } catch (err) {
        console.error("Ошибка загрузки документов для куратора:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при загрузке документов." });
    }
});

// --- НОВЫЙ API ДОКУМЕНТОВ: УТВЕРЖДЕНИЕ КУРАТОРОМ ---
app.put('/api/documents/approve/:docId', authenticateToken, checkRole(['Куратор']), async (req, res) => {
    try {
        const { docId } = req.params;

        const docResult = await pool.query(
            'SELECT * FROM documents WHERE id = $1', 
            [docId]
        );
        const doc = docResult.rows[0];

        if (!doc) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }
        
        if (doc.status !== 'Ожидает утверждения Куратором') {
             return res.status(400).json({ success: false, message: `Документ должен быть в статусе "Ожидает утверждения Куратором" для завершения.` });
        }
        
        // Обновить статус на 'Завершено'
        await pool.query(
            'UPDATE documents SET status = $1 WHERE id = $2',
            ['Завершено', docId]
        );

        res.json({ success: true, message: `Документ "${doc.title}" успешно утвержден и завершен.` });

    } catch (err) {
        console.error("Ошибка утверждения документа куратором:", err);
        res.status(500).json({ success: false, message: "Ошибка сервера при утверждении документа." });
    }
});


// --- API ДОКУМЕНТОВ: СКАЧИВАНИЕ (ТОЛЬКО КУРАТОР) ---
app.get('/api/documents/download/:docId', authenticateToken, checkRole(['Куратор']), async (req, res) => {
    try {
        const documentId = req.params.docId;

        // 1. Получить данные документа
        const docResult = await pool.query('SELECT * FROM documents WHERE id = $1', [documentId]);
        const doc = docResult.rows[0];

        if (!doc) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }
        
        // 2. Проверить статус (для скачивания нужен утвержденный документ)
        if (doc.status !== 'Ожидает утверждения Куратором' && doc.status !== 'Завершено') {
             return res.status(403).json({ success: false, message: `Документ не готов к скачиванию. Текущий статус: ${doc.status}` });
        }


        const submittedData = doc.submitted_data;
        const templateParts = documentTemplates[doc.template_name].parts;

        let content = `=====================================================================\n`;
        content += `ДОКУМЕНТ: ${doc.title} (ID: ${documentId})\n`;
        content += `ШАБЛОН: ${doc.template_name}\n`;
        content += `СТАТУС: ${doc.status}\n`;
        content += `=====================================================================\n\n`;
        
        content += `СОДЕРЖАНИЕ ДОКУМЕНТА:\n\n`;

        // Форматирование содержания на основе шаблона и заполненных данных
        templateParts.forEach(part => {
            if (part.type === 'text') {
                content += part.content;
            } else if (part.type === 'input') {
                const value = submittedData[part.name];
                const displayValue = value ? `[${value}]` : `[${part.name} (НЕ ЗАПОЛНЕН)]`;
                content += displayValue;
            }
        });
        
        content += `\n\n=====================================================================\n`;
        content += `ФИНАЛЬНЫЕ ДАННЫЕ (RAW JSON):\n`;
        content += JSON.stringify(submittedData, null, 2);
        content += `\n\n=====================================================================\n`;

        // Установка заголовков для скачивания файла
        // ВНИМАНИЕ: Для упрощения используется .txt, но вы можете заменить на .docx
        const filename = `${doc.title}_ID${documentId}_${new Date().toISOString().slice(0, 10)}.txt`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        
        res.send(content);

    } catch (error) {
        console.error("Ошибка при скачивании документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при скачивании документа." });
    }
});


// --- ЗАПУСК СЕРВЕРА ---
initializeDb().then(() => {
    app.listen(port, () => {
        console.log(`Сервер запущен на порту ${port}`);
    });
});