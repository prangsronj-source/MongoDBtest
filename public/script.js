const message = document.querySelector('#message');
const userTable = document.querySelector('#user-table');

function showMessage(text, isError = false) {
    message.textContent = text;
    message.className = isError ? 'error' : 'success';
}

// ส่งข้อมูล JSON ด้วย POST แล้วคืนผลลัพธ์ 
async function postJSON(url, data) {
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return { ok: res.ok, body: await res.json() };
}

// สมัครสมำชิก 
document.querySelector('#register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const data = Object.fromEntries(new FormData(form));
    const { ok, body } = await postJSON('/api/register', data);
    if (ok) {
        showMessage(`สมัครสมำชิกสำเร็จยินดีต้อนรับคุณ ${body.name}`);
        form.reset();
        loadUsers();
    } else {
        showMessage(body.error, true);
    }
});

// เข้ำสู ่ระบบ 
document.querySelector('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    const { ok, body } = await postJSON('/api/login', data);
    if (ok) {
        showMessage(`เข้าสู่ระบบสำเร็จสวัสดีคุณ ${body.user.name} (${body.user.role})`);
    } else {
        showMessage(body.error, true);
    }
});

// โหลดรำยชื่อสมำชิกมำแสดงในตำรำง 
async function loadUsers() {
    const res = await fetch('/api/users');
    const users = await res.json();
    userTable.innerHTML = '';
    for (const user of users) {
        const tr = document.createElement('tr');
        for (const value of [user.username, user.name, user.email, user.role]) {
            const td = document.createElement('td');
            td.textContent = value;
            tr.appendChild(td);
        }
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'ลบ';
        deleteBtn.addEventListener('click', () => deleteUser(user.username));
        const td = document.createElement('td');
        td.appendChild(deleteBtn);
        tr.appendChild(td);
        userTable.appendChild(tr);
    }
}

// ลบบัญชี 
async function deleteUser(username) {
    if (!confirm(`ลบบัญชี ${username} ใช่หรือไม่?`)) return;
    const res = await fetch(`/api/users/${username}`, { method: 'DELETE' });
    if (res.ok) {
        showMessage(`ลบบัญชี ${username} แล้ว`);
        loadUsers();
    }
}
loadUsers(); 