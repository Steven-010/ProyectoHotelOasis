document.addEventListener('DOMContentLoaded', () => {

    const resultsContainer = document.getElementById('results-container');
    const searchSummary = document.getElementById('search-summary');
    const fechaInicioInput = document.getElementById('fecha-inicio');
    const fechaFinInput = document.getElementById('fecha-fin');
    const huespedesInput = document.getElementById('huespedes');

    // --- INICIA LA LÓGICA DEL CALENDARIO MODERNO Y CONECTADO ---
    let checkoutPicker;

    const checkinPicker = flatpickr(fechaInicioInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
        onChange: function (selectedDates) {
            if (selectedDates[0]) {
                checkoutPicker.set('minDate', selectedDates[0]);
                if (checkoutPicker.selectedDates[0] < selectedDates[0]) {
                    checkoutPicker.clear();
                }
            }
        }
    });

    checkoutPicker = flatpickr(fechaFinInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
    });
    // --- TERMINA LA LÓGICA DEL CALENDARIO ---

    // Leemos los parámetros de la URL
    const params = new URLSearchParams(window.location.search);
    const fechaInicio = params.get('inicio');
    const fechaFin = params.get('fin');
    const huespedes = params.get('huespedes');

    if (!fechaInicio || !fechaFin || !huespedes) {
        resultsContainer.innerHTML = '<p class="text-center">Por favor, realiza una búsqueda desde la página principal.</p>';
        return;
    }

    // Rellenamos los campos del formulario (usando los pickers)
    checkinPicker.setDate(fechaInicio, false); // El 'false' evita que se dispare el evento onChange
    checkoutPicker.setDate(fechaFin, false);
    huespedesInput.value = huespedes;

    // Actualizamos el resumen
    searchSummary.textContent = `Resultados del ${fechaInicio} al ${fechaFin} para ${huespedes} huéspedes.`;

    // El resto del código para buscar y mostrar resultados no cambia...
    const apiUrl = `http://localhost:4000/api/habitaciones/disponibles?inicio=${fechaInicio}&fin=${fechaFin}&huespedes=${huespedes}`;

    fetch(apiUrl)
        .then(response => response.json())
        .then(habitaciones => {
            mostrarResultados(habitaciones);
        })
        .catch(error => console.error('Hubo un problema con la búsqueda:', error));


    // =====================================================================================
//      REEMPLAZA TU FUNCIÓN 'mostrarResultados' COMPLETA CON ESTA VERSIÓN
// =====================================================================================

function mostrarResultados(habitaciones) {
    resultsContainer.innerHTML = '';

    if (habitaciones.length === 0) {
        resultsContainer.innerHTML = '<div class="alert alert-warning text-center">No se encontraron habitaciones disponibles para los criterios seleccionados.</div>';
        return;
    }

    // Objeto para mapear el nombre del servicio con el icono de Bootstrap
    const iconosServicios = {
        'WiFi': 'bi-wifi',
        'TV': 'bi-tv',
        'Aire acondicionado': 'bi-snow',
        'Minibar': 'bi-cup-straw',
        'Jacuzzi': 'bi-hot-tub' 
    };

    const params = new URLSearchParams(window.location.search);
    const fechaInicio = params.get('inicio');
    const fechaFin = params.get('fin');
    const huespedes = params.get('huespedes');

    habitaciones.forEach(habitacion => {
        
        // 1. LÓGICA PARA LOS ICONOS DE SERVICIOS (LA PARTE QUE FALTABA)

        const serviciosHTML = `
            <div class="service-icon me-3" title="WiFi Gratis">
                <i class="bi bi-wifi"></i>
                <span>WiFi</span>
            </div>
            <div class="service-icon me-3" title="Televisión">
                <i class="bi bi-tv"></i>
                <span>TV</span>
            </div>
            <div class="service-icon me-3" title="Aire Acondicionado">
                <i class="bi bi-snow"></i>
                <span>AC</span>
            </div>
        `;

        // 2. LÓGICA PARA EL ENLACE (LA PARTE QUE FALTABA)
        const enlaceDetalles = `habitacion.html?id=${habitacion.id_habitacion}&inicio=${fechaInicio}&fin=${fechaFin}&huespedes=${huespedes}`;

        // 3. LÓGICA DE LA IMAGEN (CON EL SEPARADOR ';')
        const primeraImagen = habitacion.imagen_url.split(';')[0];


        // 4. ESTRUCTURA HTML COMPLETA DE LA TARJETA
        const tarjetaHTML = `
        <div class="room-card shadow-sm">
            <div class="img-container">
                <img src="${primeraImagen}" alt="Foto de ${habitacion.tipo_nombre}">
            </div>
            <div class="content">
                <h5>${habitacion.tipo_nombre} #${habitacion.numero}</h5>
                <p class="text-muted">${habitacion.descripcion}</p>
                
                <div class="service-icons d-flex flex-wrap my-3">
                    ${serviciosHTML}
                </div>

                <p class="price mt-auto">$${habitacion.precio} MXN / noche</p>
                <a href="${enlaceDetalles}" class="btn-details align-self-start">Ver Detalles y Reservar</a>
            </div>
        </div>
        `;
        resultsContainer.innerHTML += tarjetaHTML;
    });
}
});