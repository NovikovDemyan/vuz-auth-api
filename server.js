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

// --- ШАБЛОНЫ ДОКУМЕНТОВ ---
const documentTemplates = {
    'Заявление на Отпуск': {
        parts: [
            { type: "text", content: "Ректору ВУЗа, Профессору И.И. Иванову" },
            { type: "text", content: "от студента гр. " },
            { type: "variable", key: "group" },
            { type: "variable", key: "name" },
            { type: "text", content: "\nЗАЯВЛЕНИЕ\n" },
            { type: "text", content: "Прошу предоставить мне отпуск по семейным обстоятельствам с" },
            { type: "variable", key: "date_start" },
            { type: "text", content: "по" },
            { type: "variable", key: "date_end" },
            { type: "text", content: "в связи с:" },
            { type: "variable", key: "reason" },
            { type: "text", content: "\nДата: " },
            { type: "variable", key: "submit_date" },
            { type: "text", content: "\nПодпись: _____________" }
        ],
        requiredFields: ['group', 'name', 'date_start', 'date_end', 'reason']
    },
    'Объяснительная Записка': {
        parts: [
            { type: "text", content: "Декану Факультета, Профессору П.П. Петрову" },
            { type: "text", content: "от студента гр. " },
            { type: "variable", key: "group" },
            { type: "variable", key: "name" },
            { type: "text", content: "\nОБЪЯСНИТЕЛЬНАЯ ЗАПИСКА\n" },
            { type: "text", content: "Я, " },
            { type: "variable", key: "name" },
            { type: "text", content: ", студент группы " },
            { type: "variable", key: "group" },
            { type: "text", content: ", отсутствовал на занятиях " },
            { type: "variable", key: "absence_date" },
            { type: "text", content: " по следующей причине: " },
            { type: "variable", key: "reason" },
            { type: "text", content: "\nПрилагаю подтверждающие документы (если есть).\n" },
            { type: "text", content: "\nДата: " },
            { type: "variable", key: "submit_date" },
            { type: "text", content: "\nПодпись: _____________" }
        ],
        requiredFields: ['group', 'name', 'absence_date', 'reason']
    }
};

// --- КОНФИГУРАЦИЯ MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- ФУНКЦИИ-ПОМОЩНИКИ ---

/**
 * Генерирует текстовое содержимое документа на основе шаблона и данных.
 * @param {Object} doc - Объект документа из БД.
 * @param {Object} template - Шаблон документа.
 * @returns {string|null} - Сгенерированный контент или null в случае ошибки.
 */
function generateDocumentContent(doc, template) {
    if (!template || !doc.content) return null;

    try {
        // Предполагая, что doc.content - это JSON-строка с данными
        const documentData = JSON.parse(doc.content); 
        let fileContent = `--- ${doc.title} (ID: ${doc.id}) ---\n`;

        template.parts.forEach(part => {
            if (part.type === 'text') {
                // Добавляем текст и пробел для форматирования
                fileContent += part.content + ' ';
            } else if (part.type === 'variable' && part.key) {
                const dataValue = documentData[part.key] || `[${part.key} НЕ ЗАПОЛНЕНО]`;
                fileContent += dataValue + ' ';
            }
        });
        
        // Заменяем множественные пробелы и добавляем разрывы строк
        fileContent = fileContent.replace(/ {2,}/g, ' ').trim();
        fileContent = fileContent.replace(/(\n ?)+/g, '\n');
        
        // Добавление метаданных в конец
        fileContent += `\n\n--- МЕТАДАННЫЕ ДОКУМЕНТА ---\n`;
        fileContent += `Студент: ${doc.student_email}\n`;
        fileContent += `Статус: ${doc.status}\n`;
        fileContent += `Создан: ${doc.created_at}\n`;

        return fileContent;

    } catch (e) {
        console.error("Ошибка парсинга или генерации контента:", e);
        return null;
    }
}


// --- MIDDLEWARE: АУТЕНТИФИКАЦИЯ (Проверка JWT) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ success: false, message: "Необходима авторизация (токен не предоставлен)." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.error("Ошибка токена:", err.message);
            // Если токен невалиден или просрочен
            return res.status(403).json({ success: false, message: "Токен недействителен или просрочен." });
        }
        req.user = user;
        next();
    });
};

// --- MIDDLEWARE: ПРОВЕРКА РОЛЕЙ ---
const isStudentOrTeacher = (req, res, next) => {
    if (req.user.role === 'student' || req.user.role === 'teacher' || req.user.role === 'curator') {
        next();
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Студент, Преподаватель или Куратор." });
    }
};

const isTeacher = (req, res, next) => {
    if (req.user.role === 'teacher' || req.user.role === 'curator') {
        next();
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Преподаватель или Куратор." });
    }
};

const isCurator = (req, res, next) => {
    if (req.user.role === 'curator') {
        next();
    } else {
        res.status(403).json({ success: false, message: "Доступ запрещен. Требуется роль Куратор." });
    }
};

// --- 1. МАРШРУТ: РЕГИСТРАЦИЯ ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name, role } = req.body;

    if (!email || !password || !name || !role) {
        return res.status(400).json({ success: false, message: "Все поля должны быть заполнены." });
    }
    
    // Простая проверка ролей
    if (!['student', 'teacher', 'curator'].includes(role)) {
        return res.status(400).json({ success: false, message: "Недопустимая роль." });
    }

    try {
        // 1. Проверка на существование пользователя
        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ success: false, message: "Пользователь с таким email уже существует." });
        }

        // 2. Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // 3. Добавление пользователя в БД
        const result = await pool.query(
            'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id',
            [email, hashedPassword, name, role]
        );

        res.status(201).json({ 
            success: true, 
            message: "Регистрация успешна. Теперь вы можете войти.",
            userId: result.rows[0].id
        });

    } catch (error) {
        console.error("Ошибка регистрации:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при регистрации." });
    }
});


// --- 2. МАРШРУТ: АВТОРИЗАЦИЯ ---
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email и пароль должны быть заполнены." });
    }

    try {
        // 1. Поиск пользователя
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Неверный email или пароль." });
        }

        const user = result.rows[0];

        // 2. Сравнение паролей
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, message: "Неверный email или пароль." });
        }

        // 3. Генерация JWT
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name }, 
            SECRET_KEY, 
            { expiresIn: '24h' } // Токен действует 24 часа
        );

        res.status(200).json({ 
            success: true, 
            message: "Авторизация успешна.", 
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Ошибка авторизации:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при авторизации." });
    }
});


// --- 3. МАРШРУТ: ПОЛУЧЕНИЕ ИНФОРМАЦИИ О ПОЛЬЗОВАТЕЛЕ (для проверки токена на фронте) ---
app.get('/api/auth/me', authenticateToken, (req, res) => {
    // Если токен валиден, req.user содержит данные
    res.status(200).json({
        success: true,
        user: {
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
            role: req.user.role
        }
    });
});


// --- 4. МАРШРУТ: ПОЛУЧЕНИЕ СПИСКА ВСЕХ ПОЛЬЗОВАТЕЛЕЙ (КУРАТОР) ---
app.get('/api/users', authenticateToken, isCurator, async (req, res) => {
    try {
        const usersResult = await pool.query('SELECT id, email, name, role FROM users ORDER BY id');
        res.status(200).json({ success: true, users: usersResult.rows });
    } catch (error) {
        console.error("Ошибка получения списка пользователей:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении списка пользователей." });
    }
});


// --- 5. МАРШРУТ: ИЗМЕНЕНИЕ РОЛИ ПОЛЬЗОВАТЕЛЯ (КУРАТОР) ---
app.post('/api/users/update-role', authenticateToken, isCurator, async (req, res) => {
    const { email, newRole } = req.body;

    if (!email || !newRole) {
        return res.status(400).json({ success: false, message: "Необходимо указать email и новую роль." });
    }

    if (!['student', 'teacher', 'curator'].includes(newRole)) {
        return res.status(400).json({ success: false, message: "Недопустимая роль." });
    }

    try {
        const result = await pool.query(
            'UPDATE users SET role = $1 WHERE email = $2 RETURNING id',
            [newRole, email]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: "Пользователь не найден." });
        }

        res.status(200).json({ 
            success: true, 
            message: `Роль пользователя ${email} успешно изменена на ${newRole}.` 
        });

    } catch (error) {
        console.error("Ошибка изменения роли:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при изменении роли." });
    }
});


// --- 6. МАРШРУТ: ПОЛУЧЕНИЕ ДОСТУПНЫХ ШАБЛОНОВ ---
app.get('/api/documents/templates', authenticateToken, isStudentOrTeacher, (req, res) => {
    // Отправляем только названия шаблонов
    const templateNames = Object.keys(documentTemplates);
    res.status(200).json({ 
        success: true, 
        templates: templateNames.map(name => ({
            title: name,
            requiredFields: documentTemplates[name].requiredFields
        }))
    });
});


// --- 7. МАРШРУТ: СОЗДАНИЕ НОВОГО ДОКУМЕНТА (СТУДЕНТ) ---
app.post('/api/documents/create', authenticateToken, async (req, res) => {
    const { title, content } = req.body;
    const studentEmail = req.user.email; 

    if (!title || !content) {
        return res.status(400).json({ success: false, message: "Название и контент документа обязательны." });
    }

    // 1. Проверка существования шаблона
    if (!documentTemplates[title]) {
        return res.status(400).json({ success: false, message: "Неизвестный тип документа." });
    }
    
    // 2. Поиск случайного преподавателя для назначения
    try {
        const teachersResult = await pool.query(
            'SELECT id FROM users WHERE role = $1 ORDER BY RANDOM() LIMIT 1', 
            ['teacher']
        );

        if (teachersResult.rows.length === 0) {
            return res.status(503).json({ success: false, message: "Нет доступных преподавателей для назначения." });
        }
        
        const teacherId = teachersResult.rows[0].id;

        // 3. Сохранение документа в БД
        const result = await pool.query(
            `INSERT INTO documents (title, student_email, content, teacher_id) 
             VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
            [title, studentEmail, JSON.stringify(content), teacherId]
        );

        res.status(201).json({ 
            success: true, 
            message: "Документ успешно создан и отправлен на проверку.",
            documentId: result.rows[0].id
        });

    } catch (error) {
        console.error("Ошибка создания документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при создании документа." });
    }
});


// --- 8. МАРШРУТ: ПОЛУЧЕНИЕ ДОКУМЕНТОВ СТУДЕНТА ---
app.get('/api/documents/my', authenticateToken, async (req, res) => {
    const studentEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            `SELECT 
                d.id, 
                d.title, 
                d.status, 
                d.created_at,
                u.name AS teacher_name
             FROM documents d
             JOIN users u ON d.teacher_id = u.id
             WHERE d.student_email = $1 
             ORDER BY d.created_at DESC`,
            [studentEmail]
        );

        res.status(200).json({ success: true, documents: documentsResult.rows });

    } catch (error) {
        console.error("Ошибка получения документов студента:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов студента." });
    }
});


// --- 9. МАРШРУТ: ПОЛУЧЕНИЕ ДОКУМЕНТОВ ДЛЯ ПРЕПОДАВАТЕЛЯ (НА ПРОВЕРКЕ) ---
app.get('/api/documents/pending', authenticateToken, isTeacher, async (req, res) => {
    const teacherId = req.user.id;

    try {
        const documentsResult = await pool.query(
            `SELECT 
                id, 
                title, 
                student_email, 
                status, 
                created_at 
             FROM documents 
             WHERE teacher_id = $1 AND status = $2
             ORDER BY created_at ASC`,
            [teacherId, 'pending']
        );

        res.status(200).json({ success: true, documents: documentsResult.rows });

    } catch (error) {
        console.error("Ошибка получения документов преподавателя:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов преподавателя." });
    }
});


// --- 10. МАРШРУТ: ОБНОВЛЕНИЕ СТАТУСА ДОКУМЕНТА (ПРЕПОДАВАТЕЛЬ) ---
app.post('/api/documents/update-status/:documentId', authenticateToken, isTeacher, async (req, res) => {
    const documentId = req.params.documentId;
    const { newStatus } = req.body;
    const teacherId = req.user.id;

    if (!['approved', 'rejected', 'pending'].includes(newStatus)) {
        return res.status(400).json({ success: false, message: "Недопустимый статус." });
    }

    try {
        // Проверка, что документ назначен этому преподавателю
        const checkResult = await pool.query(
            'SELECT teacher_id FROM documents WHERE id = $1', 
            [documentId]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }

        if (checkResult.rows[0].teacher_id !== teacherId) {
            return res.status(403).json({ success: false, message: "У вас нет прав для изменения статуса этого документа." });
        }

        // Обновление статуса
        const updateResult = await pool.query(
            'UPDATE documents SET status = $1 WHERE id = $2 RETURNING id',
            [newStatus, documentId]
        );

        res.status(200).json({ 
            success: true, 
            message: `Статус документа ID ${documentId} обновлен на ${newStatus}.` 
        });

    } catch (error) {
        console.error("Ошибка обновления статуса:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при обновлении статуса." });
    }
});


// --- 11. МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ДОКУМЕНТОВ (КУРАТОР) ---
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
        console.error("Ошибка получения всех документов:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении всех документов." });
    }
});


// --- 12. МАРШРУТ: ПОЛУЧЕНИЕ ОДНОГО ДОКУМЕНТА (ДЕТАЛИ) ---
app.get('/api/documents/:documentId', authenticateToken, isStudentOrTeacher, async (req, res) => {
    const documentId = req.params.documentId;
    const userRole = req.user.role;
    const userId = req.user.id;
    const userEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            `SELECT 
                d.id, 
                d.title, 
                d.student_email, 
                d.content,
                d.status, 
                d.created_at,
                u.name AS teacher_name,
                u.id AS teacher_id
             FROM documents d
             JOIN users u ON d.teacher_id = u.id
             WHERE d.id = $1`,
            [documentId]
        );

        if (documentsResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }

        const doc = documentsResult.rows[0];

        // Проверка прав доступа:
        // 1. Куратор имеет доступ всегда.
        // 2. Преподаватель имеет доступ, если он назначен.
        // 3. Студент имеет доступ, если он является автором.
        if (userRole === 'curator' || 
            (userRole === 'teacher' && doc.teacher_id === userId) ||
            (userRole === 'student' && doc.student_email === userEmail)) {
            
            // Удаляем teacher_id, оставляем только teacher_name
            delete doc.teacher_id;
            
            // Контент хранится как JSON-строка, преобразуем обратно в объект
            doc.content = JSON.parse(doc.content);

            res.status(200).json({ success: true, document: doc });
        } else {
            res.status(403).json({ success: false, message: "Доступ запрещен. У вас нет прав на просмотр этого документа." });
        }

    } catch (error) {
        console.error("Ошибка получения документа:", error);
        res.status(500).json({ success: false, message: "Критическая ошибка сервера при получении документа." });
    }
});


// --- 13. МАРШРУТ: СКАЧИВАНИЕ ДОКУМЕНТА (СТУДЕНТ/ПРЕПОДАВАТЕЛЬ/КУРАТОР) ---
app.get('/api/documents/download/:documentId', authenticateToken, isStudentOrTeacher, async (req, res) => {
    const documentId = req.params.documentId;
    const userRole = req.user.role;
    const userId = req.user.id;
    const userEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            `SELECT 
                d.id, 
                d.title, 
                d.student_email, 
                d.content,
                d.status, 
                d.created_at,
                u.id AS teacher_id
             FROM documents d
             JOIN users u ON d.teacher_id = u.id
             WHERE d.id = $1`,
            [documentId]
        );

        // **ИСПРАВЛЕНИЕ: Проверка наличия документа**
        if (documentsResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }
        
        const doc = documentsResult.rows[0];

        // Проверка прав доступа (те же, что и для просмотра)
        if (userRole !== 'curator' && 
            !(userRole === 'teacher' && doc.teacher_id === userId) &&
            !(userRole === 'student' && doc.student_email === userEmail)) {
            return res.status(403).json({ success: false, message: "Доступ запрещен. У вас нет прав на скачивание этого документа." });
        }
        
        // --- ГЕНЕРАЦИЯ КОНТЕНТА ---
        const template = documentTemplates[doc.title];
        const fileContent = generateDocumentContent(doc, template);

        if (!fileContent) {
            console.error("КРИТИЧЕСКАЯ ОШИБКА: Не удалось сформировать контент для документа ID:", documentId);
            return res.status(500).json({ success: false, message: "Ошибка при формировании контента документа." });
        }
        // --------------------------

        // **ИСПРАВЛЕНИЕ ОШИБКИ 500: Кодирование имени файла для поддержки кириллицы (RFC 5987)**
        // 1. Формируем чистое имя файла (ASCII-часть)
        const filenameAscii = `${doc.title.replace(/\s/g, '_')}_ID${documentId}.txt`;
        // 2. Кодируем UTF-8 часть
        const filenameUtf8 = encodeURIComponent(filenameAscii);

        // 3. Устанавливаем заголовки
        res.setHeader(
            'Content-Disposition', 
            // Используем оба формата для максимальной совместимости с кириллицей
            `attachment; filename=\"${filenameAscii}\"; filename*=utf-8''${filenameUtf8}`
        );
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.send(fileContent);

    } catch (error) {
        console.error("КРИТИЧЕСКАЯ ОШИБКА при скачивании документа:", error);
        res.status(500).json({ success: false, message: "Критическая ошибка сервера при скачивании документа." });
    }
});


// --- ЗАПУСК СЕРВЕРА ---
app.listen(port, () => {
    console.log(`Сервер запущен на http://localhost:${port}`);
});