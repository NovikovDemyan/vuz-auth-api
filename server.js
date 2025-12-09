// auth_api/server.js - ФИНАЛЬНАЯ ВЕРСИЯ С ФУНКЦИЕЙ СКАЧИВАНИЯ DOCX

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg'); 
require('dotenv').config();

// НОВЫЙ ИМПОРТ ДЛЯ РАБОТЫ С DOCX (требует npm install docx)
const { Document, Packer, Paragraph, TextRun, AlignmentType, HeadingLevel } = require('docx'); 

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
            { type: "text", content: "Я, Студент " },
            { type: "input", name: "Фамилия_Имя", role: "Студент" },
            { type: "text", content: ", прошу предоставить мне отпуск с " },
            { type: "input", name: "Дата_Начала", role: "Студент" },
            { type: "text", content: " по " },
            { type: "input", name: "Дата_Окончания", role: "Студент" },
            { type: "text", content: ". Приказ о согласовании №" },
            { type: "input", name: "Номер_Приказа_Ректора", role: "Преподаватель" }, 
            { type: "text", content: " от " },
            { type: "input", name: "Дата_Приказа_Ректора", role: "Преподаватель" }, 
            { type: "text", content: "." }
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
            { type: "text", content: ". Статус проверки Куратором: " },
            { type: "input", name: "Статус_Куратора", role: "Преподаватель" },
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
            { type: "text", content: ". Дата утверждения: " },
            { type: "input", name: "Дата_Утверждения_Декана", role: "Преподаватель" },
            { type: "text", content: "." }
        ]
    }
};

// Функция для создания таблиц (без изменений)
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
                submitted_data JSONB, 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await pool.query(queryDocuments);
        console.log('Таблица documents успешно создана или уже существует.');


        // Добавление тестовых пользователей
        const usersToInsert = [
            { name: 'Куратор Иван', email: 'curator@vuz.ru', role: 'Куратор' },
            { name: 'Преподаватель Петр', email: 'teacher@vuz.ru', role: 'Преподаватель' },
            { name: 'Студент Антон', email: 'student@vuz.ru', role: 'Студент' }
        ];

        for (const user of usersToInsert) {
            const check = await pool.query('SELECT 1 FROM users WHERE email = $1', [user.email]);
            if (check.rowCount === 0) {
                const hashedPassword = await bcrypt.hash('123456', SALT_ROUNDS); 
                await pool.query(
                    'INSERT INTO users (name, email, hashedPassword, role) VALUES ($1, $2, $3, $4)',
                    [user.name, user.email, hashedPassword, user.role]
                );
                console.log(`Тестовый пользователь (${user.email}, ${user.role}) добавлен. Пароль: 123456`);
            }
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


// --- МАРШРУТЫ АУТЕНТИФИКАЦИИ И УПРАВЛЕНИЯ РОЛЯМИ ---

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


// --- 6. МАРШРУТ: СОЗДАНИЕ НОВОГО ДОКУМЕНТА (ПРЕПОДАВАТЕЛЬ) ---
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
            [finalTitle, studentEmail, template, finalTeacherId, teacherData || {}] 
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


// --- 7. МАРШРУТ: ПОЛУЧЕНИЕ ДОКУМЕНТОВ ДЛЯ ЗАПОЛНЕНИЯ (СТУДЕНТ) ---
app.get('/api/documents/student', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Студент') {
        return res.status(403).json({ success: false, message: "Доступ разрешен только для Студентов." });
    }
    
    const studentEmail = req.user.email;

    try {
        const documentsResult = await pool.query(
            'SELECT id, title, template, status, submitted_data FROM documents WHERE student_email = $1 AND status IN ($2, $3, $4) ORDER BY created_at DESC',
            [studentEmail, 'Ожидает заполнения', 'Заполнено', 'Завершено'] // Студент видит все свои документы
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


// --- 8. МАРШРУТ: ОТПРАВКА ЗАПОЛНЕННОГО ДОКУМЕНТА (СТУДЕНТ) ---
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
            'SELECT submitted_data FROM documents WHERE id = $1 AND student_email = $2 AND status = $3',
            [documentId, studentEmail, 'Ожидает заполнения']
        );

        if (currentDoc.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден, не предназначен для вас или уже заполнен.` });
        }
        
        const existingData = currentDoc.rows[0].submitted_data || {};
        
        // Объединяем старые и новые данные
        const finalSubmittedData = { ...existingData, ...studentData };
        
        // Обновляем статус на "Заполнено" (Ожидает финальной проверки Преподавателя)
        const result = await pool.query(
            'UPDATE documents SET status = $1, submitted_data = $2 WHERE id = $3 AND student_email = $4 RETURNING id',
            ['Заполнено', finalSubmittedData, documentId, studentEmail]
        );


        res.status(200).json({ 
            success: true, 
            message: `Документ "${documentId}" успешно заполнен и отправлен Преподавателю на проверку.` 
        });
    } catch (error) {
        console.error("Ошибка при отправке заполненного документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при отправке документа." });
    }
});


// --- 9. МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ДОКУМЕНТОВ, СОЗДАННЫХ ПРЕПОДАВАТЕЛЕМ ---
app.get('/api/documents/teacher', authenticateToken, isTeacher, async (req, res) => {
    
    const teacherId = req.user.id; 

    try {
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


// --- МАРШРУТ: ФИНАЛИЗАЦИЯ/УТВЕРЖДЕНИЕ ДОКУМЕНТА (ПРЕПОДАВАТЕЛЬ) ---
app.put('/api/documents/finalize/:id', authenticateToken, isTeacher, async (req, res) => {
    const documentId = req.params.id;
    const { finalTeacherData } = req.body; 
    const teacherId = req.user.id;

    if (!finalTeacherData || Object.keys(finalTeacherData).length === 0) {
         return res.status(400).json({ success: false, message: "Отсутствуют финальные данные для заполнения." });
    }

    try {
        const currentDoc = await pool.query(
            'SELECT submitted_data, status FROM documents WHERE id = $1 AND teacher_id = $2',
            [documentId, teacherId]
        );

        if (currentDoc.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Документ с ID ${documentId} не найден или не принадлежит вам.` });
        }
        
        const existingData = currentDoc.rows[0].submitted_data || {};
        
        // Объединяем старые и новые данные
        const finalSubmittedData = { ...existingData, ...finalTeacherData };
        
        // 3. Обновляем документ и меняем статус на "Завершено"
        const result = await pool.query(
            'UPDATE documents SET status = $1, submitted_data = $2 WHERE id = $3 AND teacher_id = $4 RETURNING id',
            ['Завершено', finalSubmittedData, documentId, teacherId]
        );

        res.status(200).json({ 
            success: true, 
            message: `Документ "${documentId}" успешно завершен и утвержден. Теперь он виден Куратору.` 
        });
    } catch (error) {
        console.error("Ошибка при финализации документа:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при финализации документа." });
    }
});


// --- МАРШРУТ: ПОЛУЧЕНИЕ ВСЕХ ДОКУМЕНТОВ (КУРАТОР) ---
app.get('/api/documents/curator', authenticateToken, isCurator, async (req, res) => {
    
    try {
        const documentsResult = await pool.query(
            `SELECT id, title, student_email, template, status, submitted_data, created_at, teacher_id 
             FROM documents 
             ORDER BY created_at DESC`
        );
        
        res.status(200).json({ 
            success: true, 
            documents: documentsResult.rows 
        });

    } catch (error) {
        console.error("Ошибка получения документов для Куратора:", error);
        res.status(500).json({ success: false, message: "Ошибка сервера при получении документов." });
    }
});


// --- ИЗМЕНЕННЫЙ МАРШРУТ: СКАЧИВАНИЕ ДОКУМЕНТА (КУРАТОР) - ГЕНЕРАЦИЯ DOCX ---
app.get('/api/documents/download/:id', authenticateToken, isCurator, async (req, res) => {
    const documentId = parseInt(req.params.id);

    try {
        // Получаем документ, включая email преподавателя и имя студента
        const result = await pool.query(
            `SELECT d.title, d.status, d.submitted_data, d.template, d.created_at, u.email as teacher_email, u2.name as student_name
             FROM documents d
             JOIN users u ON d.teacher_id = u.id
             JOIN users u2 ON d.student_email = u2.email
             WHERE d.id = $1`,
            [documentId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: "Документ не найден." });
        }

        const doc = result.rows[0];
        const templateParts = doc.template.parts;
        const submittedData = doc.submitted_data || {};
        const createdAt = new Date(doc.created_at).toLocaleString('ru-RU');
        
        // --- 1. Создание элементов DOCX ---
        const docxContent = [
            new Paragraph({
                text: `Портал ВУЗа - Документ: ${doc.title}`,
                heading: HeadingLevel.HEADING_1,
                alignment: AlignmentType.CENTER,
                spacing: { before: 200, after: 200 }
            }),
             new Paragraph({
                text: `ID Документа: ${documentId} | Статус: ${doc.status} | Создан: ${createdAt}`,
                alignment: AlignmentType.LEFT,
                spacing: { after: 100 }
            }),
             new Paragraph({
                text: `Студент: ${doc.student_name} (${doc.student_email}) | Преподаватель (Создатель): ${doc.teacher_email}`,
                alignment: AlignmentType.LEFT,
                spacing: { after: 200 }
            }),
            new Paragraph({ text: '=================================================================' }),
        ];

        // --- 2. Форматирование содержания на основе шаблона и заполненных данных ---
        templateParts.forEach(part => {
            if (part.type === 'text') {
                // Обычный текст
                docxContent.push(new Paragraph({
                    children: [
                        new TextRun(part.content)
                    ],
                    spacing: { after: 100 }
                }));
            } else if (part.type === 'input') {
                const value = submittedData[part.name];
                const displayValue = value || `[${part.name} (НЕ ЗАПОЛНЕН)]`;
                
                // Выделение заполненного поля жирным шрифтом и курсивом
                docxContent.push(new Paragraph({
                    children: [
                        new TextRun({
                            text: `${part.name} (${part.role}): `,
                            bold: true,
                        }),
                        new TextRun({
                            text: displayValue,
                            bold: true,
                            italics: true,
                            color: value ? "004085" : "FF0000" // Синий, если заполнено, Красный, если нет
                        })
                    ],
                    spacing: { after: 100 }
                }));
            }
        });
        
        docxContent.push(new Paragraph({ text: '=================================================================' }));
        docxContent.push(new Paragraph({ text: 'ФИНАЛЬНЫЕ ДАННЫЕ (RAW JSON):', heading: HeadingLevel.HEADING_3 }));
        
        // Добавление RAW JSON в виде моноширинного текста
        docxContent.push(new Paragraph({
            children: [
                new TextRun({
                    text: JSON.stringify(submittedData, null, 2),
                    font: 'Courier New',
                    size: 18, // 9pt
                })
            ]
        }));


        // --- 3. Генерация DOCX ---
        const document = new Document({
            sections: [{
                children: docxContent,
            }],
        });

        // Преобразование документа в бинарный буфер
        const buffer = await Packer.toBuffer(document);

        // --- 4. Отправка ответа ---
        const filename = `${doc.title}_ID${documentId}_${new Date().toISOString().slice(0, 10)}.docx`;
        // Устанавливаем заголовок Content-Type для DOCX
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        
        res.send(buffer);

    } catch (error) {
        console.error("Ошибка при скачивании документа:", error);
        res.status(500).json({ success: false, message: "Ошибка при генерации или скачивании DOCX." });
    }
});


app.listen(port, () => {
    console.log(`Сервер API запущен на порту ${port}`);
});