// upload.js

// Hàm này sẽ chạy ngay khi trang được tải
document.addEventListener('DOMContentLoaded', () => {
    // 1. Lấy thông tin người dùng từ localStorage
    const profile = JSON.parse(localStorage.getItem('profile') || '{}');
    const policyInput = document.getElementById('policy');
    const uploadButton = document.querySelector('#uploadForm button');
    const fileInput = document.getElementById('ehrFile');

    // 2. === LOGIC CHUẨN HÓA POLICY ===
    // Logic này PHẢI KHỚP với logic chuẩn hóa thuộc tính trong keygen.js
    if (profile.role && profile.department) {
        const roleAttr = `ROLE${profile.role.toUpperCase()}`;
        const deptAttr = `DEPT${profile.department.toUpperCase()}`;
        
        // Tạo policy với định dạng đúng mà backend có thể hiểu được
        policyInput.value = `${roleAttr} AND ${deptAttr}`;

    } else if (profile.role === 'Patient' && profile.patient_id) {
        // Xử lý riêng cho bệnh nhân (nếu có)
        // Chuẩn hóa: "patient_id:12345" -> "PATIENTID_12345"
        const patientAttr = `PATIENTID${profile.patient_id}`;
        policyInput.value = patientAttr;
        
    } else {
        // 3. Xử lý trường hợp người dùng thiếu thông tin cần thiết
        policyInput.value = "Tài khoản chưa đủ thông tin để tạo policy.";
        // Vô hiệu hóa nút upload và input file để ngăn người dùng thực hiện thao tác không hợp lệ
        if (uploadButton) uploadButton.disabled = true;
        if (fileInput) fileInput.disabled = true;

        // Hiển thị cảnh báo ngay lập tức
        const alertBox = document.getElementById('alert');
        alertBox.textContent = "Không thể upload file vì tài khoản của bạn thiếu thông tin (Role/Department) để tạo chính sách truy cập.";
        alertBox.className = "alert alert-warning";
        alertBox.classList.remove('d-none');
    }
});


// Listener cho sự kiện submit form
document.getElementById('uploadForm').addEventListener('submit', async e => {
    e.preventDefault();
    const alertBox = document.getElementById('alert');
    alertBox.classList.add('d-none');
    const file = document.getElementById('ehrFile').files[0];
    const policy = document.getElementById('policy').value;

    // Kiểm tra lại lần cuối trước khi gửi
    if (!file || !policy || policy.includes("Tài khoản chưa đủ thông tin")) {
        alertBox.textContent = 'Vui lòng chọn file và đảm bảo tài khoản có đủ thông tin để tạo policy.';
        alertBox.className = 'alert alert-danger';
        alertBox.classList.remove('d-none');
        return;
    }

    try {
        // Nút upload sẽ hiển thị trạng thái "Đang tải lên..."
        const uploadButton = e.target.querySelector('button');
        const originalButtonText = uploadButton.textContent;
        uploadButton.disabled = true;
        uploadButton.textContent = 'Đang tải lên...';

        // Gọi API với policy đã được chuẩn hóa
        const { record_id } = await uploadEhr(file, policy);

        alertBox.textContent = `Upload và mã hóa file thành công! Record ID của bạn là: ${record_id}`;
        alertBox.className = 'alert alert-success';
        alertBox.classList.remove('d-none');
        
        // Reset form sau khi thành công
        e.target.reset();

    } catch(err) {
        console.error("Upload error response:", err);
        // Cung cấp thông báo lỗi chi tiết hơn nếu có thể
        let errorMessage = 'Lỗi không xác định trong quá trình upload.';
        if (err.msg) {
            errorMessage = err.msg;
        } else if (err.error && err.error.includes("policy")) {
            errorMessage = "Lỗi cú pháp trong policy. Vui lòng liên hệ quản trị viên.";
        }
        alertBox.textContent = errorMessage;
        alertBox.className = 'alert alert-danger';
        alertBox.classList.remove('d-none');
    } finally {
        // Khôi phục lại trạng thái nút bấm dù thành công hay thất bại
        const uploadButton = e.target.querySelector('button');
        uploadButton.disabled = false;
        uploadButton.textContent = 'Upload';
    }
});