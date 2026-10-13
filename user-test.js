const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

const MONGO_URL = 'mongodb://localhost:27017';
const DATABASE_NAME = 'account-db';

let users = null;

async function createUser(username, name, email, password) {
    const passwordHash = await bcrypt.hash(password, 10);

    const doc = {
        username,
        name,
        email,
        passwordHash,
        createdAt: new Date()
    };

    const result = await users.insertOne(doc);

    console.log(`สร้างผู้ใช้ ${username} แล้ว id: ${result.insertedId}`);
}

async function checkLogin(username, password) {
    const user = await users.findOne({ username: username });

    if (!user) {
        return console.log(`${username}: ไม่พบบัญชีนี้`);
    }

    const ok = await bcrypt.compare(password, user.passwordHash);

    console.log(
        `${username}: ${ok ? 'เข้าสู่ระบบสำเร็จ' : 'รหัสผ่านไม่ถูกต้อง'}`
    );
}

async function main() {
    const client = new MongoClient(MONGO_URL);

    await client.connect();

    users = client.db(DATABASE_NAME).collection('users');

    await createUser(
        'somchai',
        'สมชาย ใจดี',
        'somchai@example.com',
        'P@ssw0rd'
    );

    await checkLogin('somchai', 'P@ssw0rd');
    await checkLogin('somchai', '123456');
    await checkLogin('somsri', 'P@ssw0rd');

    // projection: ไม่เอาฟิลด์ passwordHash ออกมา
    const list = await users
        .find({}, { projection: { passwordHash: 0 } })
        .toArray();

    console.log(list);

    await client.close();
}

main().catch(console.error);