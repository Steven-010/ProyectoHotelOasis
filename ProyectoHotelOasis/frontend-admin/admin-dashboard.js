// admin-dashboard.js

document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('adminAuthToken');
    // Si no hay token, lo redirigimos al login para seguridad
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    // Función para actualizar las tarjetas de estadísticas
    function actualizarEstadisticas(stats) {
        document.getElementById('total-reservas').textContent = stats.totalReservas;
        document.getElementById('tasa-ocupacion').textContent = `${stats.tasaOcupacion}%`;
        // Podríamos añadir más tarjetas aquí si quisiéramos
    }

    // Función para construir la tabla de actividad reciente
    function llenarTablaActividad(actividad) {
        const tbody = document.getElementById('actividad-reciente-body');
        tbody.innerHTML = ''; // Limpiamos la tabla por si acaso

        if (actividad.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center p-6">No hay actividad reciente.</td></tr>';
            return;
        }
        
        // Mapeo de estados a clases de CSS para las insignias de colores
        const statusMap = {
            'Confirmada': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
            'Pendiente': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
            'Cancelada': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
            // Añadimos los que faltan de tu diseño
            'Checked In': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
            'Checked Out': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
        };

        actividad.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-border-light dark:border-border-dark';
            
            tr.innerHTML = `
                <th scope="row" class="px-6 py-4 font-medium text-foreground-light dark:text-foreground-dark whitespace-nowrap">${item.nombre} ${item.apellido}</th>
                <td class="px-6 py-4">${item.numero_habitacion}</td>
                <td class="px-6 py-4">${new Date(item.fecha_inicio).toLocaleDateString()}</td>
                <td class="px-6 py-4">${new Date(item.fecha_fin).toLocaleDateString()}</td>
                <td class="px-6 py-4">
                    <span class="px-2 py-1 text-xs font-medium rounded-full ${statusMap[item.estado] || statusMap['Pendiente']}">${item.estado}</span>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }


    // Hacemos la llamada a nuestro nuevo endpoint del servidor
    fetch('http://localhost:4000/api/admin/dashboard-stats', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            // Si el token es inválido o no es admin, redirigimos a login
            if (response.status === 401 || response.status === 403) {
                 localStorage.removeItem('adminAuthToken');
                 window.location.href = 'login.html';
            }
            throw new Error('Error al obtener los datos del dashboard.');
        }
        return response.json();
    })
    .then(data => {
        actualizarEstadisticas(data);
        llenarTablaActividad(data.actividadReciente);
    })
    .catch(error => {
        console.error('Error:', error);
        // Podríamos mostrar un mensaje de error en la página si quisiéramos
    });
});