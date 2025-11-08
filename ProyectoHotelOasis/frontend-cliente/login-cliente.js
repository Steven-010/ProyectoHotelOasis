document.getElementById('login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    fetch('http://localhost:4000/api/clientes/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, contrasena: password })
    })
        .then(response => {
            if (!response.ok) throw new Error('Credenciales inválidas');
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
            document.getElementById('error-message').textContent = error.message;
        });
});