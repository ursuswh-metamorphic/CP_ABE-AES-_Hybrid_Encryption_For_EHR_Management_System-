// login
document.getElementById('loginForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  try {
    const { access_token, role, department, patient_id } = await login(email, password);
    localStorage.setItem('token', access_token);
    localStorage.setItem('profile', JSON.stringify({ role, department, patient_id }));
    window.location.href = 'upload.html';
  } catch(err) {
    const a = document.getElementById('alert');
    a.textContent = err.msg || 'Lỗi đăng nhập';
    a.classList.remove('d-none');
  }
});

// register
document.getElementById('regForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  const data = {
    username: f.username.value,
    email: f.email.value,
    password: f.password.value,
    role: f.role.value,
    department: f.role.value==='Patient'? null : f.department.value,
    patient_id: f.role.value==='Patient'? f.patient_id.value : null
  };
  try {
    await register(data);
    window.location.href = 'login.html';
  } catch(err) {
    const a = document.getElementById('alert');
    a.textContent = err.msg || 'Lỗi đăng ký';
    a.classList.remove('d-none');
  }
});
