// set policy on load
const profile = JSON.parse(localStorage.getItem('profile')||'{}');
const policyInput = document.getElementById('policy');
if (profile.role === 'Patient') {
  policyInput.value = `patient_id:${profile.patient_id}`;
} else {
  policyInput.value = `role:${profile.role} AND department:${profile.department}`;
}

document.getElementById('uploadForm').addEventListener('submit', async e => {
  e.preventDefault();
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  const file = document.getElementById('ehrFile').files[0];
  try {
    const { record_id } = await uploadEhr(file, policyInput.value);
    alert.textContent = `Upload thành công! ID: ${record_id}`;
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');
  } catch(err) {
    // alert.textContent = err.msg || 'Lỗi upload';
    // alert.className = 'alert alert-danger';
    // alert.classList.remove('d-none');

    console.error("Upload error response:", err);
    const message = err.detail || err.msg || 'Lỗi upload';
    alert.textContent = message;
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});
