document.addEventListener('DOMContentLoaded', () => {
    
    const loginButton = document.getElementById('login-button');
    const profileMenu = document.getElementById('profile-menu');
    const profileNameNav = document.getElementById('profile-name-nav');
    const logoutButtonNav = document.getElementById('logout-button-nav');

    const token = localStorage.getItem('authToken');

    // Función para decodificar el token JWT
    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    if (token) {
        // Si encontramos un token, el usuario ha iniciado sesión
        const userData = parseJwt(token);
        
        if (userData) {
            // 1. Ocultamos el botón de Login
            loginButton.classList.add('d-none');
            
            // 2. Mostramos el menú de perfil
            profileMenu.classList.remove('d-none');

            // 3. Ponemos el nombre del usuario en el menú
            profileNameNav.textContent = userData.nombre;

            // 4. Hacemos que el botón de "Cerrar Sesión" del menú funcione
            logoutButtonNav.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('authToken');
                window.location.href = 'index.html'; // Lo mandamos al inicio
            });
        }
    }
    // Si no hay token, no hacemos nada. La página mostrará el botón de Login por defecto.
});