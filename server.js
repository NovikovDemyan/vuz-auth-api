require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const PizZip = require('pizzip');
const Docxtemplater = require('docxtemplater');

const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

/* ===================== НАСТРОЙКИ ===================== */

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false
});

/* ===================== JWT ===================== */

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function isTeacherOrCurator(req, res, next) {
    if (req.user.role === 'Преподаватель' || req.user.role === 'Куратор') {
        next();
    } else {
        res.sendStatus(403);
    }
}

/* ===================== AUTH ===================== */

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Неверные данные' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Неверные данные' });

    const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '8h' }
    );

    res.json({ token, role: user.role });
});

/* ===================== ДОКУМЕНТЫ ===================== */

/* --- СОЗДАНИЕ ДОКУМЕНТА (ПРЕПОДАВАТЕЛЬ) --- */
app.post('/api/documents/create',
    authenticateToken,
    isTeacherOrCurator,
    async (req, res) => {

    const { title, student_email, teacher_data } = req.body;

    await pool.query(
        `INSERT INTO documents
         (title, student_email, teacher_id, status, submitted_data, template_file)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
            title,
            student_email,
            req.user.id,
            'Ожидает заполнения',
            teacher_data || {},
            'document.docx'
        ]
    );

    res.json({ message: 'Документ отправлен студенту' });
});

/* --- ДОКУМЕНТЫ СТУДЕНТА --- */
app.get('/api/documents/student',
    authenticateToken,
    async (req, res) => {

    if (req.user.role !== 'Студент') {
        return res.sendStatus(403);
    }

    const result = await pool.query(
        `SELECT id, title, status
         FROM documents
         WHERE student_email = $1`,
        [req.user.email]
    );

    res.json(result.rows);
});

/* --- СКАЧИВАНИЕ WORD-ШАБЛОНА (СТУДЕНТ) --- */
app.get('/api/documents/template/:id',
    authenticateToken,
    async (req, res) => {

    if (req.user.role !== 'Студент') {
        return res.sendStatus(403);
    }

    const documentId = parseInt(req.params.id, 10);

    const result = await pool.query(
        `SELECT template_file, student_email
         FROM documents
         WHERE id = $1`,
        [documentId]
    );

    const doc = result.rows[0];
    if (!doc || doc.student_email !== req.user.email) {
        return res.sendStatus(404);
    }

    const templatePath = path.join(
        __dirname,
        'templates',
        doc.template_file || 'document.docx'
    );

    res.setHeader(
        'Content-Disposition',
        'attachment; filename="Шаблон_документа.docx"'
    );
    res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    );

    res.sendFile(templatePath);
});

/* --- ОТПРАВКА ЗАПОЛНЕННЫХ ДАННЫХ (СТУДЕНТ) --- */
app.put('/api/documents/submit/:id',
    authenticateToken,
    async (req, res) => {

    if (req.user.role !== 'Студент') {
        return res.sendStatus(403);
    }

    const documentId = parseInt(req.params.id, 10);

    await pool.query(
        `UPDATE documents
         SET submitted_data = $1,
             status = 'На проверке'
         WHERE id = $2 AND student_email = $3`,
        [
            req.body,
            documentId,
            req.user.email
        ]
    );

    res.json({ message: 'Документ отправлен на проверку' });
});

/* --- СКАЧИВАНИЕ ФИНАЛЬНОГО DOCX (ПРЕПОД / КУРАТОР) --- */
app.get('/api/documents/download/:id',
    authenticateToken,
    isTeacherOrCurator,
    async (req, res) => {

    const documentId = parseInt(req.params.id, 10);

    const result = await pool.query(
        `SELECT title, submitted_data, template_file
         FROM documents
         WHERE id = $1`,
        [documentId]
    );

    const doc = result.rows[0];
    if (!doc) return res.sendStatus(404);

    const templatePath = path.join(
        __dirname,
        'templates',
        doc.template_file || 'document.docx'
    );

    const content = fs.readFileSync(templatePath, 'binary');
    const zip = new PizZip(content);

    const docx = new Docxtemplater(zip, {
        paragraphLoop: true,
        linebreaks: true
    });

    docx.render(doc.submitted_data || {});

    const buffer = docx
        .getZip()
        .generate({ type: 'nodebuffer' });

    res.setHeader(
        'Content-Disposition',
        `attachment; filename="${doc.title}.docx"`
    );
    res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    );

    res.send(buffer);
});

/* ===================== SERVER ===================== */

app.listen(PORT, () => {
    console.log(`🚀 Server started on port ${PORT}`);
});
