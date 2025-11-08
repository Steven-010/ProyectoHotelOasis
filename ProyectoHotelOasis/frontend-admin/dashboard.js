// dashboard.js (VERSIÓN FINAL Y COMPLETA)
let revenueChartInstance;
let occupancyChartInstance;
let datosReporteActual = [];

document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('adminAuthToken');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    function parseJwt(token) {
        try { return JSON.parse(atob(token.split('.')[1])); } catch (e) { return null; }
    }

    const userData = parseJwt(token);
    const esAdmin = userData && userData.rol === 'Administrador';

    if (esAdmin) {
        document.querySelectorAll('.admin-only').forEach(item => {
            item.classList.remove('hidden');
        });
    }

    const sidebarLinks = document.querySelectorAll('#sidebarMenu .nav-link');
    const tabPanes = document.querySelectorAll('main .tab-pane');

    // REEMPLAZA ESTE BLOQUE EN TU dashboard.js
    sidebarLinks.forEach(link => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            const targetId = link.getAttribute('href');

            sidebarLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.querySelector(targetId).classList.add('active');

            // --- ¡AQUÍ ESTÁ LA MODIFICACIÓN CLAVE! ---
            if (targetId === '#dashboard-content') {
                if (esAdmin) { cargarEstadisticasAdmin(); }
                else { cargarEstadisticasEmpleado(); }
            } else if (targetId === '#reservas-content') {
                cargarReservas();
            } else if (targetId === '#habitaciones-content') {
                cargarHabitaciones();
            } else if (targetId === '#personal-content') {
                // LLAMADA A LA NUEVA FUNCIÓN DE PERSONAL
                cargarPersonal();
            } else if (targetId === '#reportes-content') {
                // LLAMADA A LA NUEVA FUNCIÓN DE REPORTES
                document.querySelector('.period-btn[data-periodo="semanal"]').click();
            }
        });
    });


    // --- LÓGICA DEL BUSCADOR EN TIEMPO REAL PARA RESERVAS ---
    const searchInputReservas = document.getElementById('search-reservas');

    searchInputReservas.addEventListener('keyup', () => {
        // 1. Obtenemos el texto de búsqueda y lo convertimos a minúsculas para que no distinga mayúsculas/minúsculas.
        const searchTerm = searchInputReservas.value.toLowerCase();

        // 2. Seleccionamos el cuerpo de la tabla y todas sus filas.
        const tableBody = document.getElementById('reservas-table-body');
        const rows = tableBody.getElementsByTagName('tr');

        // 3. Recorremos cada fila de la tabla.
        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];

            // Si la primera celda dice "Cargando..." o "No se encontraron...", no hacemos nada con ella.
            if (row.getElementsByTagName('td').length > 1) {
                const rowText = row.textContent.toLowerCase(); // Obtenemos todo el texto de la fila en minúsculas.

                // 4. Comparamos si el texto de la fila incluye el término de búsqueda.
                if (rowText.includes(searchTerm)) {
                    row.style.display = ''; // Si coincide, nos aseguramos de que la fila sea visible.
                } else {
                    row.style.display = 'none'; // Si no coincide, ocultamos la fila.
                }
            }
        }
    });


    function crearGraficaReservas() {
        fetch('http://localhost:4000/api/admin/reservations-chart-data', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(chartData => {
                const ctx = document.getElementById('reservationsChart').getContext('2d');
                if (window.myReservationsChart instanceof Chart) {
                    window.myReservationsChart.destroy();
                }
                window.myReservationsChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartData.labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
                        datasets: [{
                            label: 'Nº de Reservas',
                            data: chartData.data,
                            backgroundColor: 'rgba(32, 201, 151, 0.1)',
                            borderColor: '#20c997',
                            borderWidth: 3,
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: { y: { beginAtZero: true } },
                        plugins: { legend: { display: false } }
                    }
                });
            }).catch(console.error);
    }

    function cargarEstadisticasAdmin() {
        fetch('http://localhost:4000/api/admin/dashboard-stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(data => {
                document.getElementById('total-reservas').textContent = data.totalReservas;
                document.getElementById('tasa-ocupacion').textContent = `${data.tasaOcupacion}%`;
                document.getElementById('habitaciones-disponibles').textContent = data.habitacionesDisponibles;

                // ===== ¡ESTA ES LA PARTE QUE SE HABÍA PERDIDO Y AHORA ESTÁ CORREGIDA! =====
                const tbody = document.getElementById('actividad-reciente-body');
                tbody.innerHTML = '';

                if (!data.actividadReciente || data.actividadReciente.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center p-6 text-muted-light">No hay actividad reciente para mostrar.</td></tr>';
                    return;
                }

                const statusClasses = {
                    'Confirmada': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
                    'Pendiente': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
                    'Cancelada': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
                    'Check-in': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
                    'Check-out': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                };

                data.actividadReciente.forEach(item => {
                    const statusClass = statusClasses[item.estado] || 'bg-gray-100 text-gray-800';
                    tbody.innerHTML += `
                    <tr class="border-b border-border-light dark:border-border-dark">
                        <th scope="row" class="px-6 py-4 font-medium text-foreground-light dark:text-foreground-dark whitespace-nowrap">${item.nombre} ${item.apellido}</th>
                        <td class="px-6 py-4">${item.numero_habitacion}</td>
                        <td class="px-6 py-4">${new Date(item.fecha_inicio).toLocaleDateString()}</td>
                        <td class="px-6 py-4">${new Date(item.fecha_fin).toLocaleDateString()}</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-xs font-medium rounded-full ${statusClass}">${item.estado}</span>
                        </td>
                    </tr>
                `;
                });

            }).catch(console.error);

        crearGraficaReservas();
    }

    function cargarEstadisticasEmpleado() {
        fetch('http://localhost:4000/api/employee/dashboard-stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(data => {
                const dashboardContent = document.getElementById('dashboard-content');
                dashboardContent.innerHTML = `
                <header class="mb-8">
                    <h2 class="text-4xl font-bold">Dashboard</h2>
                    <p class="text-foreground-light/70 dark:text-foreground-dark/70">Resumen diario de operaciones.</p>
                </header>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <div class="bg-card-light dark:bg-card-dark p-6 rounded-lg shadow-sm border border-border-light dark:border-border-dark">
                        <h3 class="text-base font-medium text-muted-light dark:text-muted-dark mb-2">Llegadas de Hoy</h3>
                        <p class="text-4xl font-bold text-primary">${data.llegadasHoy}</p>
                    </div>
                    <div class="bg-card-light dark:bg-card-dark p-6 rounded-lg shadow-sm border border-border-light dark:border-border-dark">
                        <h3 class="text-base font-medium text-muted-light dark:text-muted-dark mb-2">Salidas de Hoy</h3>
                        <p class="text-4xl font-bold text-primary">${data.salidasHoy}</p>
                    </div>
                    <div class="bg-card-light dark:bg-card-dark p-6 rounded-lg shadow-sm border border-border-light dark:border-border-dark">
                        <h3 class="text-base font-medium text-muted-light dark:text-muted-dark mb-2">Habitaciones Disponibles</h3>
                        <p class="text-4xl font-bold text-primary">${data.habitacionesDisponibles}</p>
                    </div>
                </div>
            `;
            }).catch(error => {
                document.getElementById('dashboard-content').innerHTML = '<p class="text-red-500 font-bold">Error al cargar la vista de empleado. Por favor, recarga la página.</p>';
            });
    }

    //=============== AÑADE ESTE FRAGMENTO A DASHBOARD.JS ===============

    // --- LÓGICA PARA LA VENTANA MODAL DE DETALLES DE RESERVA ---
    const detallesReservaModal = document.getElementById('detalles-reserva-modal');
    const closeDetallesModalButton = document.getElementById('close-detalles-modal-button');
    const detallesModalBody = document.getElementById('detalles-modal-body');
    const reservasTableBody = document.getElementById('reservas-table-body');

    closeDetallesModalButton.addEventListener('click', () => detallesReservaModal.classList.add('hidden'));

    // Usamos event delegation para escuchar clics en los botones "Ver"
    reservasTableBody.addEventListener('click', (event) => {
        if (event.target.classList.contains('ver-detalles-btn')) {
            const codigoReserva = event.target.dataset.codigo;
            mostrarDetallesReserva(codigoReserva);
        }
    });

    function mostrarDetallesReserva(codigo) {
        detallesModalBody.innerHTML = '<p>Cargando detalles...</p>';
        detallesReservaModal.classList.remove('hidden');

        fetch(`http://localhost:4000/api/panel/reservas/${codigo}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(reserva => {
                const precioNoche = parseFloat(reserva.precio_por_noche);
                const noches = (new Date(reserva.fecha_fin) - new Date(reserva.fecha_inicio)) / (1000 * 3600 * 24);
                const total = precioNoche * noches;

                detallesModalBody.innerHTML = `
                <div class="space-y-4">
                    <div><strong>Cliente:</strong> ${reserva.nombre} ${reserva.apellido}</div>
                    <div><strong>Email:</strong> ${reserva.email}</div>
                    <div><strong>Habitación:</strong> ${reserva.tipo_habitacion} #${reserva.numero}</div>
                    <div><strong>Fechas:</strong> ${new Date(reserva.fecha_inicio).toLocaleDateString()} al ${new Date(reserva.fecha_fin).toLocaleDateString()} (${noches} noches)</div>
                    <div class="font-bold text-lg"><strong>Total:</strong> $${total.toFixed(2)} MXN</div>
                    <hr>
                    <div>
                        <label for="estado-reserva" class="block font-medium mb-1">Cambiar Estado:</label>
                        <select id="estado-reserva" class="w-full rounded-lg border">
                            <option value="Pendiente" ${reserva.estado === 'Pendiente' ? 'selected' : ''}>Pendiente</option>
                            <option value="Confirmada" ${reserva.estado === 'Confirmada' ? 'selected' : ''}>Confirmada</option>
                            <option value="Check-in" ${reserva.estado === 'Check-in' ? 'selected' : ''}>Check-in</option>
                            <option value="Check-out" ${reserva.estado === 'Check-out' ? 'selected' : ''}>Check-out</option>
                            <option value="Cancelada" ${reserva.estado === 'Cancelada' ? 'selected' : ''}>Cancelada</option>
                        </select>
                    </div>
                    <div class="text-right mt-4">
                        <button id="guardar-estado-btn" data-codigo="${codigo}" class="bg-primary text-white px-5 py-2 rounded-lg font-semibold">Guardar Cambios</button>
                    </div>
                </div>
            `;
            });
    }

    // Event listener para el botón "Guardar Cambios" dentro del modal
    detallesModalBody.addEventListener('click', (event) => {
        if (event.target.id === 'guardar-estado-btn') {
            const codigoReserva = event.target.dataset.codigo;
            const nuevoEstado = document.getElementById('estado-reserva').value;

            // --- ¡ESTA ES LA LÍNEA CORREGIDA! ---
            // Añadimos la dirección completa del servidor.
            fetch(`http://localhost:4000/api/panel/reservas/${codigoReserva}/estado`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ nuevoEstado })
            })
                .then(res => {
                    if (!res.ok) { // Verifica si la respuesta fue exitosa
                        return res.json().then(err => { throw new Error(err.mensaje); });
                    }
                    return res.json();
                })
                .then(data => {
                    alert(data.mensaje);
                    detallesReservaModal.classList.add('hidden');
                    cargarReservas(); // Recargamos la tabla para ver el cambio
                })
                .catch(error => {
                    console.error("Error al actualizar estado:", error);
                    alert(`No se pudo actualizar el estado: ${error.message}`);
                });
        }
    });

    document.getElementById('logout-button').addEventListener('click', () => {
        localStorage.removeItem('adminAuthToken');
        window.location.href = 'login.html';
    });


    // --- FUNCIÓN NUEVA PARA CARGAR LA TABLA DE RESERVAS ---
    function cargarReservas() {
        const tbody = document.getElementById('reservas-table-body');
        tbody.innerHTML = '<tr><td colspan="7" class="text-center p-6">Cargando reservas...</td></tr>';

        fetch('http://localhost:4000/api/panel/reservas', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(reservas => {
                tbody.innerHTML = '';
                if (reservas.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="text-center p-6">No se encontraron reservas.</td></tr>';
                    return;
                }

                const statusClasses = {
                    'Confirmada': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
                    'Pendiente': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
                    'Cancelada': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
                };

                reservas.forEach(reserva => {
                    const statusClass = statusClasses[reserva.estado] || 'bg-gray-100 text-gray-800';
                    tbody.innerHTML += `
                    <tr class="border-b border-border-light dark:border-border-dark hover:bg-accent-light/50">
                        <td class="px-6 py-4 font-medium text-foreground-light dark:text-foreground-dark">${reserva.codigo_reserva}</td>
                        <td class="px-6 py-4">${reserva.nombre} ${reserva.apellido}</td>
                        <td class="px-6 py-4">${new Date(reserva.fecha_inicio).toLocaleDateString()}</td>
                        <td class="px-6 py-4">${new Date(reserva.fecha_fin).toLocaleDateString()}</td>
                        <td class="px-6 py-4">${reserva.numero_habitacion} - ${reserva.tipo_habitacion}</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-xs font-medium rounded-full ${statusClass}">${reserva.estado}</span>
                        </td>
                        <td class="px-6 py-4 text-right">
                            <button data-codigo="${reserva.codigo_reserva}" class="ver-detalles-btn text-primary hover:underline font-semibold">Ver</button>
                        </td>
                    </tr>
                `;
                });
            }).catch(error => {
                console.error('Error al cargar reservas:', error);
                tbody.innerHTML = '<tr><td colspan="7" class="text-center p-6 text-red-500">Error al cargar las reservas.</td></tr>';
            });
    }


    //=============== REEMPLAZA TU FUNCIÓN cargarHabitaciones Y SU addEventListener CON ESTO ===============

    function cargarHabitaciones() {
        const container = document.getElementById('habitaciones-grid-container');
        container.innerHTML = '<p>Cargando estado de las habitaciones...</p>';
        const token = localStorage.getItem('adminAuthToken');

        fetch('http://localhost:4000/api/panel/habitaciones', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(habitaciones => {
                container.innerHTML = '';
                if (habitaciones.length === 0) {
                    container.innerHTML = '<p class="text-center">No hay habitaciones para mostrar.</p>';
                    return;
                }

                habitaciones.forEach(h => {
                    let statusClass = 'bg-success/10 text-success';
                    let statusText = 'Disponible';

                    if (h.estado === 'Ocupada') {
                        statusClass = 'bg-danger/10 text-danger';
                        statusText = 'Ocupada';
                    } else if (h.estado === 'Mantenimiento') {
                        statusClass = 'bg-warning/10 text-warning';
                        statusText = 'Mantenimiento';
                    } else if (h.estado_limpieza !== 'Limpia') {
                        statusClass = 'bg-info/10 text-info';
                        statusText = `Limpieza (${h.estado_limpieza})`;
                    }

                    // --- CAMBIO CLAVE: Toda la tarjeta es un botón ---
                    const cardHTML = `
                <button 
                    data-id="${h.id_habitacion}" 
                    data-numero="${h.numero}"
                    data-estado="${h.estado}"
                    data-limpieza="${h.estado_limpieza}"
                    class="room-status-card border rounded-lg p-4 text-center transition-shadow hover:shadow-lg w-full">
                    <div class="text-2xl font-bold mb-2">${h.numero}</div>
                    <div class="inline-flex items-center px-3 py-1 text-sm font-semibold rounded-full ${statusClass}">
                        <span class="w-2 h-2 rounded-full mr-2" style="background-color: currentColor;"></span>
                        ${statusText}
                    </div>
                </button>
                `;
                    container.innerHTML += cardHTML;
                });
            });
    }

    // --- LÓGICA PARA GESTIONAR EL MODAL DE ESTADO DE HABITACIÓN ---
    const habitacionesGrid = document.getElementById('habitaciones-grid-container');
    const cambiarEstadoModal = document.getElementById('cambiar-estado-modal');
    const closeModalButtonEstado = document.getElementById('close-estado-modal-button');
    const guardarNuevoEstadoBtn = document.getElementById('guardar-nuevo-estado-btn');
    const modalTitulo = document.getElementById('modal-estado-titulo');
    const selectEstado = document.getElementById('select-estado-general');
    const selectLimpieza = document.getElementById('select-estado-limpieza');

    // 1. Abrir el modal al hacer clic en una tarjeta
    habitacionesGrid.addEventListener('click', (event) => {
        const card = event.target.closest('.room-status-card');
        if (card) {
            const id = card.dataset.id;
            const numero = card.dataset.numero;
            const estadoActual = card.dataset.estado;
            const limpiezaActual = card.dataset.limpieza;

            // Guardamos el ID en el botón de guardar para usarlo después
            guardarNuevoEstadoBtn.dataset.id = id;

            // Populamos el modal con los datos actuales
            modalTitulo.textContent = `Cambiar Estado de Habitación #${numero}`;
            selectEstado.value = estadoActual;
            selectLimpieza.value = limpiezaActual;

            // Mostramos el modal
            cambiarEstadoModal.classList.remove('hidden');
        }
    });

    // 2. Cerrar el modal
    closeModalButtonEstado.addEventListener('click', () => {
        cambiarEstadoModal.classList.add('hidden');
    });

    // 3. Guardar los cambios
    guardarNuevoEstadoBtn.addEventListener('click', () => {
        const idHabitacion = guardarNuevoEstadoBtn.dataset.id;
        const nuevoEstado = selectEstado.value;
        const nuevoEstadoLimpieza = selectLimpieza.value;
        const token = localStorage.getItem('adminAuthToken');

        fetch(`http://localhost:4000/api/panel/habitaciones/${idHabitacion}/estado`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ nuevoEstado, nuevoEstadoLimpieza })
        })
            .then(res => res.json())
            .then(data => {
                alert(data.mensaje);
                cambiarEstadoModal.classList.add('hidden'); // Ocultamos el modal
                cargarHabitaciones(); // Recargamos la vista para ver el cambio
            })
            .catch(error => {
                console.error("Error al actualizar habitación:", error);
                alert("No se pudo actualizar la habitación.");
            });
    });


    function marcarHabitacionComoDisponible(idHabitacion) {
        fetch(`http://localhost:4000/api/panel/habitaciones/${idHabitacion}/estado`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ nuevoEstado: 'Disponible', nuevoEstadoLimpieza: 'Limpia' })
        })
            .then(res => res.json())
            .then(data => {
                alert(data.mensaje);
                cargarHabitaciones(); // Recargamos la vista para ver el cambio
            });
    }

    // --- LÓGICA PARA LA VENTANA MODAL DE NUEVA RESERVA ---
    const nuevaReservaModal = document.getElementById('nueva-reserva-modal');
    const nuevaReservaButton = document.querySelector('#reservas-content button');
    const closeModalButton = document.getElementById('close-modal-button');

    // Contenedor para las habitaciones y botón para ir al paso 3
    const availableRoomsContainer = document.getElementById('available-rooms-container');
    const toStep3Button = document.getElementById('to-step-3-button');
    const backToStep1Button = document.getElementById('back-to-step-1-button');
    const backToStep2Button = document.getElementById('back-to-step-2-button');

    // Almacenará temporalmente la información de la reserva
    let nuevaReservaData = {};

    // Inicializamos los calendarios modernos
    const checkinPicker = flatpickr("#modal-fecha-inicio", { dateFormat: "Y-m-d", minDate: "today" });
    const checkoutPicker = flatpickr("#modal-fecha-fin", { dateFormat: "Y-m-d", minDate: "today" });

    // Función para mostrar/ocultar la modal
    function toggleModal(show) {
        nuevaReservaModal.classList.toggle('hidden', !show);
        if (show) {
            goToStep(1); // Siempre reinicia al paso 1 al abrir
            // Limpia los campos
            checkinPicker.clear();
            checkoutPicker.clear();
            document.getElementById('modal-huespedes').value = 2;
            document.getElementById('modal-cliente-nombre').value = '';
            document.getElementById('modal-cliente-apellido').value = '';
            document.getElementById('modal-cliente-email').value = '';
        }
    }

    // Abrir y cerrar la modal
    nuevaReservaButton.addEventListener('click', () => toggleModal(true));
    closeModalButton.addEventListener('click', () => toggleModal(false));


    // Navegación entre pasos
    const modalSteps = [document.getElementById('modal-step-1'), document.getElementById('modal-step-2'), document.getElementById('modal-step-3')];
    function goToStep(stepNumber) {
        modalSteps.forEach((step, index) => step.classList.toggle('hidden', index !== (stepNumber - 1)));
    }

    document.getElementById('back-to-step-1-button').addEventListener('click', () => goToStep(1));
    document.getElementById('back-to-step-2-button').addEventListener('click', () => goToStep(2));
    toStep3Button.addEventListener('click', () => goToStep(3));

    // LÓGICA DEL PASO 1 al 2: Buscar Habitaciones
    document.getElementById('to-step-2-button').addEventListener('click', () => {
        const inicio = checkinPicker.selectedDates[0];
        const fin = checkoutPicker.selectedDates[0];
        const huespedes = document.getElementById('modal-huespedes').value;

        if (!inicio || !fin) {
            alert('Por favor, selecciona ambas fechas.');
            return;
        }

        // Guardamos los datos
        nuevaReservaData.fecha_inicio = inicio.toISOString().split('T')[0];
        nuevaReservaData.fecha_fin = fin.toISOString().split('T')[0];
        nuevaReservaData.num_huespedes = huespedes;

        availableRoomsContainer.innerHTML = '<p>Buscando habitaciones disponibles...</p>';
        toStep3Button.disabled = true; // Deshabilitamos el botón "Siguiente"
        goToStep(2);

        // Hacemos la llamada al endpoint que ya existe
        fetch(`http://localhost:4000/api/habitaciones/disponibles?inicio=${nuevaReservaData.fecha_inicio}&fin=${nuevaReservaData.fecha_fin}&huespedes=${huespedes}`)
            .then(res => res.json())
            .then(habitaciones => {
                availableRoomsContainer.innerHTML = '';
                if (habitaciones.length === 0) {
                    availableRoomsContainer.innerHTML = '<p class="text-center text-red-500">No se encontraron habitaciones disponibles para estas fechas.</p>';
                    return;
                }

                habitaciones.forEach(hab => {
                    const roomCard = document.createElement('div');
                    roomCard.className = 'room-card p-4 rounded-lg bg-subtle-light dark:bg-subtle-dark cursor-pointer';
                    roomCard.innerHTML = `
                        <p class="font-bold text-lg">${hab.tipo_nombre} #${hab.numero}</p>
                        <p class="text-sm">Capacidad: ${hab.max_personas} | Precio: $${hab.precio}/noche</p>
                    `;
                    // Guardamos el ID de la habitación en el elemento
                    roomCard.dataset.roomId = hab.id_habitacion;
                    availableRoomsContainer.appendChild(roomCard);
                });
            });
    });

    // LÓGICA DEL PASO 2: Seleccionar una Habitación
    availableRoomsContainer.addEventListener('click', (event) => {
        const selectedCard = event.target.closest('.room-card');
        if (!selectedCard) return;

        // Quitamos la selección de cualquier otra tarjeta
        availableRoomsContainer.querySelectorAll('.room-card').forEach(card => card.classList.remove('selected'));
        // Añadimos la clase de selección a la tarjeta clickeada
        selectedCard.classList.add('selected');

        // Guardamos el ID de la habitación seleccionada
        nuevaReservaData.id_habitacion = selectedCard.dataset.roomId;
        toStep3Button.disabled = false; // Habilitamos el botón "Siguiente"
    });

    // LÓGICA DEL PASO 3: Confirmar la Reserva
    document.getElementById('confirm-reservation-button').addEventListener('click', () => {
        // Recolectamos los datos del cliente
        nuevaReservaData.cliente = {
            nombre: document.getElementById('modal-cliente-nombre').value,
            apellido: document.getElementById('modal-cliente-apellido').value,
            email: document.getElementById('modal-cliente-email').value,
        };

        if (!nuevaReservaData.cliente.nombre || !nuevaReservaData.cliente.email) {
            alert('El nombre y el email del cliente son obligatorios.');
            return;
        }

        // Enviamos todo al endpoint de creación de reservas que ya existe
        fetch('http://localhost:4000/api/reservas', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(nuevaReservaData),
        })
            .then(res => res.json())
            .then(data => {
                if (data.codigo) {
                    alert(`¡Reserva creada con éxito! Código: ${data.codigo}`);
                    toggleModal(false); // Cerramos la modal
                    cargarReservas(); // Actualizamos la tabla de reservas
                } else {
                    throw new Error(data.mensaje || 'Error desconocido al crear la reserva.');
                }
            })
            .catch(error => {
                console.error('Error en la confirmación:', error);
                alert(error.message);
            });
    });

    backToStep1Button.addEventListener('click', () => goToStep(1));
    toStep3Button.addEventListener('click', () => goToStep(3));
    backToStep2Button.addEventListener('click', () => goToStep(2));

    sidebarLinks[0].click();


    // ---- LÓGICA PARA LA PESTAÑA DE GESTIÓN DE PERSONAL ----

    function cargarPersonal() {
        const tbody = document.getElementById('personal-table-body');
        tbody.innerHTML = '<tr><td colspan="4" class="text-center p-6">Cargando personal...</td></tr>';

        fetch('http://localhost:4000/api/admin/personal', { headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json())
            .then(personal => {
                tbody.innerHTML = '';
                if (personal.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center p-6">No hay personal registrado.</td></tr>';
                    return;
                }
                personal.forEach(p => {
                    if (p.activo) {
                        tbody.innerHTML += `
                        <tr class="hover:bg-accent-light/50">
                            <td class="p-4 font-medium">${p.nombre} ${p.apellido}</td>
                            <td class="p-4">${p.correo}</td>
                            <td class="p-4">${p.puesto}</td>
                            <td class="p-4 text-right flex flex-wrap justify-end gap-4">
                                <button data-id="${p.id_personal}" class="editar-personal-btn text-primary hover:underline font-semibold">Editar</button>
                                <button data-id="${p.id_personal}" class="reset-password-btn text-blue-500 hover:underline font-semibold">Cambiar Contraseña</button>
                                <button data-id="${p.id_personal}" class="baja-personal-btn text-danger hover:underline font-semibold">Dar de Baja</button>
                            </td>
                        </tr>
                    `;
                    }
                });
            });
    }

    // Lógica para el modal de ALTA de personal (sin cambios)
    const modalPersonal = document.getElementById('modal-alta-personal');
    const formPersonal = document.getElementById('form-alta-personal');
    document.getElementById('abrir-modal-personal').addEventListener('click', () => modalPersonal.classList.remove('hidden'));
    document.getElementById('cerrar-modal-personal').addEventListener('click', () => modalPersonal.classList.add('hidden'));
    formPersonal.addEventListener('submit', (e) => {
        e.preventDefault();
        const nuevoEmpleado = {
            nombre: document.getElementById('personal-nombre').value,
            apellido: document.getElementById('personal-apellido').value,
            correo: document.getElementById('personal-correo').value,
            puesto: document.getElementById('personal-puesto').value,
            contrasena: document.getElementById('personal-contrasena').value
        };
        fetch('http://localhost:4000/api/admin/personal', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(nuevoEmpleado) })
            .then(res => res.json().then(data => ({ status: res.status, body: data })))
            .then(({ status, body }) => {
                alert(body.mensaje);
                if (status === 201) {
                    modalPersonal.classList.add('hidden');
                    formPersonal.reset();
                    cargarPersonal();
                }
            });
    });


    // --- NUEVA LÓGICA PARA EDITAR Y DAR DE BAJA ---
    const personalTableBody = document.getElementById('personal-table-body');
    const modalEditar = document.getElementById('modal-editar-personal');
    const formEditar = document.getElementById('form-editar-personal');
    const modalBaja = document.getElementById('modal-baja-personal');

    // Usamos event delegation para escuchar los clics en los botones de la tabla
    personalTableBody.addEventListener('click', (e) => {
        // Si se hizo clic en un botón de EDITAR
        if (e.target.classList.contains('editar-personal-btn')) {
            const id = e.target.dataset.id;
            // Hacemos un fetch para obtener los datos más recientes del empleado
            fetch(`http://localhost:4000/api/admin/personal/${id}`, { headers: { 'Authorization': `Bearer ${token}` } })
                .then(res => res.json())
                .then(empleado => {
                    // Llenamos el formulario del modal de edición
                    document.getElementById('edit-personal-id').value = empleado.id_personal;
                    document.getElementById('edit-personal-nombre').value = empleado.nombre;
                    document.getElementById('edit-personal-apellido').value = empleado.apellido;
                    document.getElementById('edit-personal-correo').value = empleado.correo;
                    document.getElementById('edit-personal-puesto').value = empleado.puesto;
                    modalEditar.classList.remove('hidden');
                });
        }

        // Si se hizo clic en un botón de DAR DE BAJA
        if (e.target.classList.contains('baja-personal-btn')) {
            const id = e.target.dataset.id;
            // Guardamos el ID en el botón de confirmación y mostramos el modal
            document.getElementById('confirmar-baja-btn').dataset.id = id;
            modalBaja.classList.remove('hidden');
        }
    });

    // Lógica para cerrar el modal de EDICIÓN
    document.getElementById('cerrar-modal-editar').addEventListener('click', () => modalEditar.classList.add('hidden'));

    // Lógica para enviar el formulario de EDICIÓN
    formEditar.addEventListener('submit', (e) => {
        e.preventDefault();
        const id = document.getElementById('edit-personal-id').value;
        const datosActualizados = {
            nombre: document.getElementById('edit-personal-nombre').value,
            apellido: document.getElementById('edit-personal-apellido').value,
            correo: document.getElementById('edit-personal-correo').value,
            puesto: document.getElementById('edit-personal-puesto').value,
        };

        fetch(`http://localhost:4000/api/admin/personal/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify(datosActualizados) })
            .then(res => res.json())
            .then(data => {
                alert(data.mensaje);
                modalEditar.classList.add('hidden');
                cargarPersonal(); // Actualizamos la tabla
            });
    });

    // Lógica para los botones del modal de BAJA
    document.getElementById('cancelar-baja-btn').addEventListener('click', () => modalBaja.classList.add('hidden'));
    document.getElementById('confirmar-baja-btn').addEventListener('click', (e) => {
        const id = e.target.dataset.id;
        fetch(`http://localhost:4000/api/admin/personal/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json())
            .then(data => {
                alert(data.mensaje);
                modalBaja.classList.add('hidden');
                cargarPersonal(); // Actualizamos la tabla
            });
    });

    // --- LÓGICA ADICIONAL PARA EL MODAL DE CAMBIO DE CONTRASEÑA ---
    const modalResetPassword = document.getElementById('modal-reset-password');
    const formResetPassword = document.getElementById('form-reset-password');

    // Añadimos el nuevo evento al listener principal de la tabla
    personalTableBody.addEventListener('click', (e) => {
        // ... (el código existente para 'editar' y 'dar de baja' NO SE TOCA)

        // Si se hizo clic en un botón de CAMBIAR CONTRASEÑA
        if (e.target.classList.contains('reset-password-btn')) {
            const id = e.target.dataset.id;
            // Guardamos el ID en el formulario y mostramos el modal
            document.getElementById('reset-password-id').value = id;
            modalResetPassword.classList.remove('hidden');
        }
    });

    // Lógica para cerrar el modal de CAMBIO DE CONTRASEÑA
    document.getElementById('cerrar-modal-reset-password').addEventListener('click', () => {
        modalResetPassword.classList.add('hidden');
        formResetPassword.reset(); // Limpiamos el formulario
    });

    // Lógica para enviar el formulario de CAMBIO DE CONTRASEÑA
    formResetPassword.addEventListener('submit', (e) => {
        e.preventDefault();
        const id = document.getElementById('reset-password-id').value;
        const nuevaContrasena = document.getElementById('new-password').value;

        fetch(`http://localhost:4000/api/admin/personal/${id}/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ nuevaContrasena })
        })
            .then(res => res.json())
            .then(data => {
                alert(data.mensaje);
                modalResetPassword.classList.add('hidden');
                formResetPassword.reset(); // Limpiamos el formulario al terminar
            });
    });


    // ---- LÓGICA PARA LA PESTAÑA DE REPORTES ----

    function crearGraficaIngresos(labels, data) {
        const ctx = document.getElementById('revenueChart').getContext('2d');
        if (revenueChartInstance) { revenueChartInstance.destroy(); }
        revenueChartInstance = new Chart(ctx, {
            type: 'line', data: { labels, datasets: [{ label: 'Ingresos', data, backgroundColor: 'rgba(32, 201, 151, 0.1)', borderColor: '#20c997', borderWidth: 3, tension: 0.4, fill: true }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });
    }

    function crearGraficaOcupacion(labels, data) {
        const ctx = document.getElementById('occupancyChart').getContext('2d');
        if (occupancyChartInstance) { occupancyChartInstance.destroy(); }
        occupancyChartInstance = new Chart(ctx, {
            type: 'bar', data: { labels, datasets: [{ label: 'Ocupación', data, backgroundColor: 'rgba(32, 201, 151, 0.5)', borderColor: '#20c997', borderWidth: 1 }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } }
        });
    }

    // Inicializamos el calendario interactivo
    const dateRangePicker = flatpickr("#report-date-range", {
        mode: "range",
        dateFormat: "Y-m-d",
        onClose: function (selectedDates) {
            if (selectedDates.length === 2) {
                document.querySelectorAll('.period-btn').forEach(btn => btn.classList.remove('active'));
                cargarReportes();
            }
        }
    });

    // Añadimos la lógica a los botones "Semanal", "Quincenal" y "Mensual"
    document.getElementById('periodo-selector').addEventListener('click', (e) => {
        if (e.target.classList.contains('period-btn')) {
            const button = e.target;
            document.querySelectorAll('.period-btn').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            const periodo = button.dataset.periodo;
            const endDate = new Date();
            let daysToSubtract = 6;

            if (periodo === 'quincenal') {
                daysToSubtract = 14;
            } else if (periodo === 'mensual') {
                daysToSubtract = 29;
            }

            const startDate = new Date();
            startDate.setDate(endDate.getDate() - daysToSubtract);
            dateRangePicker.setDate([startDate, endDate]);
            cargarReportes();
        }
    });

    // La función para cargar los datos
    function cargarReportes() {
        const selectedDates = dateRangePicker.selectedDates;
        if (selectedDates.length < 2) return;

        const inicio = selectedDates[0].toISOString().split('T')[0];
        const fin = selectedDates[1].toISOString().split('T')[0];

        document.getElementById('reporte-ingresos').textContent = 'Cargando...';
        // ... (resto del código de carga)

        fetch(`http://localhost:4000/api/admin/reportes?inicio=${inicio}&fin=${fin}`, { headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json())
            .then(data => {
                const datos = data.reporte;
                datosReporteActual = datos; // Guardamos los datos para el PDF

                // ... (resto del código para mostrar datos y gráficas)
                const totalIngresos = datos.reduce((sum, item) => sum + item.ingresos, 0);
                const promedioOcupacion = datos.length > 0 ? datos.reduce((sum, item) => sum + item.tasaOcupacion, 0) / datos.length : 0;

                document.getElementById('reporte-ingresos').textContent = `$${totalIngresos.toLocaleString('es-MX', { minimumFractionDigits: 2 })}`;
                document.getElementById('reporte-ocupacion').textContent = `${promedioOcupacion.toFixed(1)}%`;

                const finTableBody = document.getElementById('financial-report-table-body');
                const occTableBody = document.getElementById('occupancy-report-table-body');
                finTableBody.innerHTML = '';
                occTableBody.innerHTML = '';

                const labels = datos.map(d => d.label);
                const ingresosData = datos.map(d => d.ingresos);
                const ocupacionData = datos.map(d => d.tasaOcupacion.toFixed(1));

                datos.forEach(d => {
                    finTableBody.innerHTML += `<tr><td class="py-3 px-6 font-medium">${d.label}</td><td class="py-3 px-6 text-right">$${d.ingresos.toFixed(2)}</td></tr>`;
                    occTableBody.innerHTML += `<tr><td class="py-3 px-6 font-medium">${d.label}</td><td class="py-3 px-6 text-right">${d.tasaOcupacion.toFixed(1)}%</td></tr>`;
                });

                crearGraficaIngresos(labels, ingresosData);
                crearGraficaOcupacion(labels, ocupacionData);
            })
            .catch(console.error);
    }

    // ===== LA CORRECCIÓN CLAVE ESTÁ AQUÍ =====

    // Función genérica para crear y descargar el PDF
    function descargarReportePDF(titulo, headers, data, columnas) {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        doc.setFontSize(18);
        doc.text(titulo, 14, 22);
        doc.setFontSize(11);
        doc.setTextColor(100);
        const rangoFechas = dateRangePicker.input.value;
        doc.text(`Periodo del reporte: ${rangoFechas}`, 14, 29);

        doc.autoTable({
            startY: 35,
            head: [headers],
            body: data.map(fila => columnas.map(col => fila[col])),
            theme: 'striped',
            headStyles: { fillColor: [32, 201, 151] },
        });

        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(10);
            const fechaHoy = new Date().toLocaleDateString('es-MX');
            doc.text(`Página ${i} de ${pageCount} | Generado el ${fechaHoy}`, 14, doc.internal.pageSize.height - 10);
        }

        const fechaInicio = dateRangePicker.selectedDates[0].toISOString().split('T')[0];
        const fechaFin = dateRangePicker.selectedDates[1].toISOString().split('T')[0];

        // 2. Creamos el nuevo nombre de archivo dinámico.
        const nombreArchivo = `${titulo.replace(/ /g, '_')}_${fechaInicio}_a_${fechaFin}.pdf`;
        doc.save(nombreArchivo);
    }

    // Conectar los botones a la función de descarga
    document.getElementById('download-financial-pdf').addEventListener('click', () => {
        if (datosReporteActual.length === 0) return alert('Primero debes generar un reporte.');

        descargarReportePDF(
            'Reporte Financiero',
            ['Periodo', 'Ingresos ($)'],
            datosReporteActual,
            ['label', 'ingresos']
        );
    });

    document.getElementById('download-occupancy-pdf').addEventListener('click', () => {
        if (datosReporteActual.length === 0) return alert('Primero debes generar un reporte.');

        const datosFormateados = datosReporteActual.map(item => ({
            ...item,
            tasaOcupacionFormateada: `${item.tasaOcupacion.toFixed(1)}%`
        }));

        descargarReportePDF(
            'Reporte de Ocupación',
            ['Periodo', 'Tasa de Ocupación (%)'],
            datosFormateados,
            ['label', 'tasaOcupacionFormateada']
        );
    });
});