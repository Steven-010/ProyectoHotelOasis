document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('authToken');
    if (!token) {
        window.location.href = 'login-cliente.html';
        return;
    }

    // --- REFERENCIAS A TODOS LOS ELEMENTOS DEL DOM ---
    const userSessionContainer = document.getElementById('user-session');
    const profilePicEl = document.getElementById('profile-pic');
    const profileNameSidebarEl = document.getElementById('profile-name-sidebar');
    const reservationsContainer = document.getElementById('reservations-container');
    const menuTabs = document.getElementById('profile-menu-tabs');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const logoutButton = document.getElementById('logout-button');
    const editProfileForm = document.getElementById('edit-profile-form');
    const editNombreInput = document.getElementById('edit-nombre');
    const editApellidoInput = document.getElementById('edit-apellido');
    const editEmailInput = document.getElementById('edit-email');

    // --- LÓGICA DE PESTAÑAS (TABS) ---
    menuTabs.addEventListener('click', (event) => {
        const targetLink = event.target.closest('a');
        if (!targetLink || targetLink.id === 'logout-button') return;
        event.preventDefault();

        // Limpiar estilos de todos los enlaces del menú
        menuTabs.querySelectorAll('a').forEach(link => {
            link.classList.remove('bg-gray-100', 'text-primary');
            link.classList.add('hover:bg-gray-100', 'text-subtle-light');
        });

        // Ocultar todos los paneles de contenido
        tabPanes.forEach(pane => pane.classList.remove('active'));

        // Activar el enlace y panel seleccionados
        targetLink.classList.add('bg-gray-100', 'text-primary');
        targetLink.classList.remove('hover:bg-gray-100', 'text-subtle-light');
        const targetPaneId = targetLink.getAttribute('href').substring(1);
        document.getElementById(targetPaneId).classList.add('active');
    });

    // --- FUNCIÓN PARA DECODIFICAR EL TOKEN JWT ---
    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    // --- CARGAR DATOS DEL USUARIO ---
    const userData = parseJwt(token);
    if (userData) {
        const userName = userData.nombre.toUpperCase();
        profileNameSidebarEl.textContent = userName;

        // Rellenar menú de la cabecera
        userSessionContainer.innerHTML = `
            <button class="flex items-center space-x-2 bg-gray-100 px-4 py-2 rounded-full">
                <span class="font-semibold text-sm">${userName}</span>
                <span class="material-icons text-subtle-light text-xl">arrow_drop_down</span>
            </button>
        `;

        // Rellenar los campos del formulario de edición con los datos actuales
        editNombreInput.value = userData.nombre;
        editApellidoInput.value = userData.apellido;
        editEmailInput.value = userData.email;
    }
    
    // --- CARGAR HISTORIAL DE RESERVAS (CON MANEJO DE ERRORES MEJORADO) ---
    fetch('http://localhost:4000/api/clientes/mis-reservas', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
        .then(response => {
            // Si la respuesta no es OK (ej. 403 Forbidden), lanzamos un error para que lo capture el .catch()
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.mensaje || 'Error del servidor'); });
            }
            return response.json();
        })
        .then(reservas => {
            reservationsContainer.innerHTML = '';
            if (!reservas || reservas.length === 0) {
                reservationsContainer.innerHTML = '<p class="text-subtle-light">Aún no tienes ninguna reserva.</p>';
                return;
            }

            reservas.forEach(reserva => {
                let badgeClasses = 'bg-yellow-100 text-yellow-800'; // "Pendiente"
                if (reserva.estado === 'Confirmada') {
                    badgeClasses = 'bg-green-100 text-green-800';
                } else if (reserva.estado === 'Cancelada') {
                    badgeClasses = 'bg-gray-100 text-gray-800';
                }

                const reservaCardHTML = `
                <div class="border border-gray-200 rounded-lg p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center hover:shadow-md transition-shadow duration-300">
                    <div>
                        <h4 class="font-bold text-lg">Habitación ${reserva.tipo_nombre} #${reserva.numero}</h4>
                        <p class="text-sm text-subtle-light mt-1">Código: <span class="font-mono">${reserva.codigo_reserva}</span></p>
                        <div class="flex items-center text-sm text-subtle-light mt-2 space-x-4">
                            <span>Check-in: ${new Date(reserva.fecha_inicio).toLocaleDateString()}</span>
                            <span>Check-out: ${new Date(reserva.fecha_fin).toLocaleDateString()}</span>
                        </div>
                    </div>
                    <div class="mt-4 sm:mt-0">
                        <span class="px-3 py-1 text-sm font-semibold rounded-full ${badgeClasses}">${reserva.estado}</span>
                    </div>
                </div>
            `;
                reservationsContainer.innerHTML += reservaCardHTML;
            });
        })
        .catch(error => {
            console.error('Error al cargar reservas:', error);
            reservationsContainer.innerHTML = `<p class="text-red-500 font-bold">No se pudieron cargar tus reservas. Causa: ${error.message}</p>`;
        });

    // --- LÓGICA PARA ENVIAR EL FORMULARIO DE EDICIÓN ---
    editProfileForm.addEventListener('submit', (event) => {
        event.preventDefault();
        const updatedData = {
            nombre: editNombreInput.value,
            apellido: editApellidoInput.value
        };

        fetch('http://localhost:4000/api/clientes/perfil', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(updatedData)
        })
            .then(response => response.json())
            .then(data => {
                alert(data.mensaje);
                // Para que los cambios se reflejen en el saludo, es necesario un nuevo token.
                // Forzamos un logout para que el usuario vuelva a iniciar sesión y obtenga el token actualizado.
                alert('Para ver los cambios reflejados, por favor, inicia sesión de nuevo.');
                localStorage.removeItem('authToken');
                window.location.href = 'login-cliente.html';
            })
            .catch(error => {
                console.error('Error al actualizar:', error);
                alert('Hubo un error al guardar los cambios.');
            });
    });

    // --- LÓGICA PARA ENVIAR EL FORMULARIO DE CAMBIO DE CONTRASEÑA ---
    const editForm = document.getElementById('edit-profile-form');

    editForm.addEventListener('submit', (event) => {
        event.preventDefault(); // Prevenimos que se envíen ambos a la vez

        const contrasenaActual = document.getElementById('contrasena-actual').value;
        const nuevaContrasena = document.getElementById('nueva-contrasena').value;

        // Si los campos de contraseña tienen texto, intentamos cambiar la contraseña
        if (contrasenaActual && nuevaContrasena) {
            fetch('http://localhost:4000/api/clientes/cambiar-contrasena', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ contrasenaActual, nuevaContrasena })
            })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.mensaje); });
                    }
                    return response.json();
                })
                .then(data => {
                    alert(data.mensaje); // "Contraseña actualizada exitosamente"
                    // Forzamos logout por seguridad
                    localStorage.removeItem('authToken');
                    window.location.href = 'login-cliente.html';
                })
                .catch(error => {
                    alert(`Error: ${error.message}`);
                });
        }
    });

    // --- LÓGICA DE CERRAR SESIÓN ---
    logoutButton.addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.removeItem('authToken');
        window.location.href = 'index.html';
    });
});