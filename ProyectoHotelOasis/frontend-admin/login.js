// login.js (REEMPLAZAR TODO EL ARCHIVO)

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    loginForm.addEventListener('submit', (event) => {
        event.preventDefault();
        // Cambiamos 'username' por 'email' para que coincida con el input
        const email = document.getElementById('username').value; 
        const password = document.getElementById('password').value;

        // 1. URL CORREGIDA: Apuntamos a la nueva ruta /api/admin/login
        fetch('http://localhost:4000/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                // 2. CAMPOS CORREGIDOS: Enviamos 'correo' y 'contrasena' como espera el backend
                correo: email,
                contrasena: password
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.mensaje || 'Credenciales inválidas'); });
            }
            return response.json();
        })
        .then(data => {
            // Guardamos el token con el nombre que espera dashboard.js
            localStorage.setItem('adminAuthToken', data.token);
            window.location.href = 'dashboard.html'; 
        })
        .catch(error => {
            errorMessage.textContent = error.message;
        });
    });
});