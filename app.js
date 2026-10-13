const express = require('express');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017';
const DATABASE_NAME = 'account-db';
const PORT = Number(process.env.PORT) || 3000;
const SESSION_COOKIE = 'dbtest_sid';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(express.static('public'));

let users = null;
const sessions = new Map(); // Demo session store; use a persistent store in production.
const HIDE_PASSWORD = { projection: { passwordHash: 0 } };

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function readSession(req) {
    const cookieHeader = req.headers.cookie || '';
    const entry = cookieHeader.split(';').map(v => v.trim()).find(v => v.startsWith(`${SESSION_COOKIE}=`));
    if (!entry) return null;
    const sid = decodeURIComponent(entry.slice(SESSION_COOKIE.length + 1));
    const session = sessions.get(sid);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(sid);
        return null;
    }
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    return session;
}

function requireLogin(req, res, next) {
    const session = readSession(req);
    if (!session) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });
    req.session = session;
    next();
}

function requireAdmin(req, res, next) {
    if (req.session?.role !== 'admin') {
        return res.status(403).json({ error: 'เฉพาะ Admin เท่านั้นที่ทำรายการนี้ได้' });
    }
    next();
}

// POST /api/register — สมัครสมาชิก
app.post('/api/register', async (req, res, next) => {
    try {
        const { username, name, email, password } = req.body || {};
        if (![username, name, email, password].every(v => typeof v === 'string' && v.trim())) {
            return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
        }
        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
            return res.status(400).json({ error: 'username ต้องเป็น a-z, 0-9 หรือ _ ยาว 3–20 ตัว' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร' });
        }
        const user = { username, name: name.trim(), email: email.trim().toLowerCase(), role: 'member', createdAt: new Date() };
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await users.insertOne({ ...user, passwordHash });
        return res.status(201).json({ _id: result.insertedId, ...user });
    } catch (err) {
        if (err.code === 11000) return res.status(409).json({ error: 'username หรือ email นี้ถูกใช้แล้ว' });
        next(err);
    }
});

// POST /api/login — ตรวจรหัสผ่านและสร้าง session
app.post('/api/login', async (req, res, next) => {
    try {
        const { username, password } = req.body || {};
        if (typeof username !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: 'กรุณากรอก username และรหัสผ่าน' });
        }
        const user = await users.findOne({ username });
        const ok = user && await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ error: 'username หรือรหัสผ่านไม่ถูกต้อง' });

        // Rotate session ID on login to reduce session-fixation risk.
        const sid = crypto.randomBytes(32).toString('hex');
        sessions.set(sid, { username: user.username, role: user.role, expiresAt: Date.now() + SESSION_TTL_MS });
        res.cookie(SESSION_COOKIE, sid, {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: SESSION_TTL_MS,
            path: '/',
        });
        await users.updateOne({ _id: user._id }, { $inc: { loginCount: 1 }, $set: { lastLoginAt: new Date() } });
        return res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: { username: user.username, name: user.name, role: user.role } });
    } catch (err) { next(err); }
});

app.post('/api/logout', (req, res) => {
    const cookieHeader = req.headers.cookie || '';
    const entry = cookieHeader.split(';').map(v => v.trim()).find(v => v.startsWith(`${SESSION_COOKIE}=`));
    if (entry) sessions.delete(decodeURIComponent(entry.slice(SESSION_COOKIE.length + 1)));
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', path: '/' });
    res.json({ message: 'ออกจากระบบแล้ว' });
});

// GET /api/me — ข้อมูลผู้ใช้ที่เข้าสู่ระบบ
app.get('/api/me', requireLogin, async (req, res, next) => {
    try {
        const user = await users.findOne({ username: req.session.username }, HIDE_PASSWORD);
        if (!user) return res.status(401).json({ error: 'ไม่พบบัญชีผู้ใช้' });
        res.json({ username: user.username, name: user.name, role: user.role });
    } catch (err) { next(err); }
});

// GET /api/users?q=คำค้น — ค้นหาชื่อแบบไม่สนตัวพิมพ์เล็ก/ใหญ่
app.get('/api/users', async (req, res, next) => {
    try {
        const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
        const filter = q ? { name: { $regex: escapeRegex(q), $options: 'i' } } : {};
        const list = await users.find(filter, HIDE_PASSWORD).sort({ createdAt: -1 }).limit(100).toArray();
        res.json(list);
    } catch (err) { next(err); }
});

// PATCH /api/users/:username/password — ต้อง login เป็นเจ้าของบัญชีและยืนยันรหัสผ่านเดิม
app.patch('/api/users/:username/password', requireLogin, async (req, res, next) => {
    try {
        if (req.session.username !== req.params.username) {
            return res.status(403).json({ error: 'เปลี่ยนรหัสผ่านได้เฉพาะบัญชีของตัวเอง' });
        }
        const { currentPassword, newPassword } = req.body || {};
        if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
            return res.status(400).json({ error: 'กรุณากรอกรหัสผ่านเดิมและรหัสผ่านใหม่' });
        }
        if (newPassword.length < 8) return res.status(400).json({ error: 'รหัสผ่านใหม่ต้องยาวอย่างน้อย 8 ตัวอักษร' });
        const user = await users.findOne({ username: req.params.username });
        if (!user) return res.status(404).json({ error: 'ไม่พบบัญชีผู้ใช้' });
        if (!(await bcrypt.compare(currentPassword, user.passwordHash))) {
            return res.status(401).json({ error: 'รหัสผ่านเดิมไม่ถูกต้อง' });
        }
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await users.updateOne({ _id: user._id }, { $set: { passwordHash, passwordChangedAt: new Date() } });
        // Invalidate all sessions for this account, including the current one.
        for (const [sid, session] of sessions.entries()) {
            if (session.username === user.username) sessions.delete(sid);
        }
        res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', path: '/' });
        return res.json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ กรุณาเข้าสู่ระบบใหม่' });
    } catch (err) { next(err); }
});

// DELETE /api/users/:username — เฉพาะ Admin ที่ login แล้ว
app.delete('/api/users/:username', requireLogin, requireAdmin, async (req, res, next) => {
    try {
        if (req.session.username === req.params.username) {
            return res.status(400).json({ error: 'ไม่สามารถลบบัญชี Admin ที่กำลังใช้งานอยู่ได้' });
        }
        const result = await users.deleteOne({ username: req.params.username });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้นี้' });
        res.status(204).end();
    } catch (err) { next(err); }
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์' });
});

async function main() {
    const client = new MongoClient(MONGO_URL);
    await client.connect();
    users = client.db(DATABASE_NAME).collection('users');
    await users.createIndex({ username: 1 }, { unique: true });
    await users.createIndex({ email: 1 }, { unique: true });
    console.log('เชื่อมต่อ MongoDB สำเร็จ');
    app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
}

main().catch(err => {
    console.error('เชื่อมต่อฐานข้อมูลไม่สำเร็จ:', err.message);
    process.exit(1);
});
