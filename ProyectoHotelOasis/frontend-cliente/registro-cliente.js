document.getElementById('registro-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const nombre = document.getElementById('nombre').value;
    const apellido = document.getElementById('apellido').value;
    const email = document.getElementById('email').value;
    const telefono = document.getElementById('telefono').value;
    const password = document.getElementById('password').value;

    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    errorMessage.textContent = '';
    successMessage.textContent = '';

    fetch('http://localhost:4000/api/clientes/registro', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nombre, apellido, email, telefono, contrasena: password })
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.mensaje || 'Error al registrar'); });
            }
            return response.json();
        })
        .then(data => {
            // Si es un login, guardamos el token
            if (data.token) localStorage.setItem('authToken', data.token);

            // Verificamos si hay una URL guardada para redirigir
            const redirectUrl = localStorage.getItem('redirectUrlAfterLogin');

            if (redirectUrl) {
                // Si hay una, lo llevamos allí y limpiamos el storage
                localStorage.removeItem('redirectUrlAfterLogin');
                window.location.href = redirectUrl;
            } else {
                // Si no, lo llevamos a su perfil (comportamiento normal)
                window.location.href = 'perfil.html';
            }
        })
        .catch(error => {
            errorMessage.textContent = error.message;
        });
});