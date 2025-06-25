// keygen.js

document.getElementById('genBtn').addEventListener('click', async () => {
  const alertBox = document.getElementById('alert');
  alertBox.classList.add('d-none');
  
  // 1. Lấy thông tin hồ sơ người dùng từ localStorage.
  // Đây là nguồn dữ liệu đáng tin cậy, không lấy từ ô input nữa.
  const profile = JSON.parse(localStorage.getItem('profile') || '{}');
  
  // 2. === BƯỚC CHUẨN HÓA QUAN TRỌNG NHẤT ===
  // Tạo mảng thuộc tính sẽ được gửi đến API với định dạng chuẩn.
  const attributesForApi = [];
  if (profile.role) {
    // Chuẩn hóa: "Doctor" -> "ROLE_DOCTOR"
    attributesForApi.push(`ROLE${profile.role.toUpperCase()}`);
  }
  if (profile.department) {
    // Chuẩn hóa: "Cardiology" -> "DEPT_CARDIOLOGY"
    attributesForApi.push(`DEPT${profile.department.toUpperCase()}`);
  }
  // ===========================================

  // 3. Kiểm tra xem người dùng có thuộc tính hợp lệ không.
  if (attributesForApi.length === 0) {
    alertBox.textContent = 'Tài khoản của bạn không có thuộc tính (role/department) để tạo khóa.';
    alertBox.className = 'alert alert-danger';
    alertBox.classList.remove('d-none');
    return;
  }

  try {
    // 4. Gọi API `keygen` với mảng thuộc tính đã được chuẩn hóa.
    // Backend sẽ nhận được: ["ROLE_DOCTOR", "DEPT_CARDIOLOGY"]
    const responseData = await keygen(attributesForApi);

    // 5. Tạo một blob chứa TOÀN BỘ đối tượng JSON trả về từ server.
    // Điều này giúp file key chứa nhiều thông tin hữu ích hơn (attributes, user_id, timestamp).
    // JSON.stringify(..., null, 2) giúp định dạng file JSON cho dễ đọc.
    const blob = new Blob([JSON.stringify(responseData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    // 6. Đặt tên file là .json và cho phép tải về.
    // Tên file được lấy từ gợi ý của backend.
    a.href = url;
    a.download = responseData.instructions?.save_as || `user_${responseData.user_id}_sk.json`;
    
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a); // Dọn dẹp thẻ <a> sau khi click
    URL.revokeObjectURL(url); // Giải phóng bộ nhớ

    // 7. Hiển thị thông báo thành công cho người dùng.
    const attributesText = attributesForApi.join(', ');
    alertBox.innerHTML = `Đã tạo và tải file Secret Key (.json) thành công! <br><strong>Thuộc tính được sử dụng:</strong> ${attributesText}`;
    alertBox.className = 'alert alert-success';
    alertBox.classList.remove('d-none');

  } catch (err) {
    // 8. Xử lý lỗi nếu có vấn đề khi gọi API.
    console.error("Keygen error:", err);
    alertBox.textContent = err.msg || err.message || 'Một lỗi không xác định đã xảy ra trong quá trình tạo khóa.';
    alertBox.className   = 'alert alert-danger';
    alertBox.classList.remove('d-none');
  }
});