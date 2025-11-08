document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const roomId = params.get('id');
    const fechaInicioParam = params.get('inicio');
    const fechaFinParam = params.get('fin');
    const huespedesParam = params.get('huespedes');

    if (!roomId) {
        document.querySelector('main').innerHTML = '<h1 class="text-center">Habitación no especificada.</h1>';
        return;
    }

    // Referencias a todos los elementos del HTML
    const roomNameEl = document.getElementById('room-name');
    const roomDescriptionEl = document.getElementById('room-description');
    const roomServicesEl = document.getElementById('room-services');
    const roomPriceEl = document.getElementById('room-price');
    const mainPhotoEl = document.getElementById('main-room-photo');
    const fechaInicioInput = document.getElementById('fecha-inicio');
    const fechaFinInput = document.getElementById('fecha-fin');
    const priceCalculationEl = document.getElementById('price-calculation');
    const totalPriceEl = document.getElementById('total-price');
    const bookingForm = document.getElementById('booking-form');

    // Lógica del botón "Continuar con la Reserva"
    bookingForm.addEventListener('submit', (event) => {
        event.preventDefault(); // Prevenimos el envío por defecto

        const token = localStorage.getItem('authToken');

        if (token) {
            // Si el usuario SÍ ha iniciado sesión, lo llevamos a la página de confirmación
            const fechaInicio = document.getElementById('fecha-inicio').value;
            const fechaFin = document.getElementById('fecha-fin').value;
            const url = `confirmacion.html?id=${roomId}&inicio=${fechaInicio}&fin=${fechaFin}&huespedes=${huespedesParam}`;
            window.location.href = url;
        } else {
            // Si el usuario NO ha iniciado sesión...
            // 1. Guardamos la URL a la que quería ir
            const targetUrl = `confirmacion.html?id=${roomId}&inicio=${fechaInicioInput.value}&fin=${fechaFinInput.value}&huespedes=${huespedesParam}`;
            localStorage.setItem('redirectUrlAfterLogin', targetUrl);

            // 2. Mostramos el modal de autenticación
            const authModal = new bootstrap.Modal(document.getElementById('authModal'));
            authModal.show();
        }
    });

    let precioPorNoche = 0;
    let checkoutPicker;

    // Configuración del calendario de Check-in
    const checkinPicker = flatpickr(fechaInicioInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
        onChange: function (selectedDates) {
            if (selectedDates[0]) {
                checkoutPicker.set('minDate', selectedDates[0]);
                if (checkoutPicker.selectedDates[0] < selectedDates[0]) checkoutPicker.clear();
            }
            calcularPrecioTotal();
        }
    });

    // Configuración del calendario de Check-out
    checkoutPicker = flatpickr(fechaFinInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
        onChange: function () {
            calcularPrecioTotal();
        }
    });

    // Rellenamos las fechas iniciales
    checkinPicker.setDate(fechaInicioParam, false);
    checkoutPicker.setDate(fechaFinParam, false);
    const galleryContainer = document.getElementById('gallery-container');
    // Pedimos los datos de la habitación al servidor
fetch(`http://localhost:4000/api/habitaciones/${roomId}`)
    .then(response => {
        if (!response.ok) { // Captura el error 500 aquí
            throw new Error(`Error ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(habitacion => {
        precioPorNoche = habitacion.precio;
        roomNameEl.textContent = `${habitacion.nombre} #${habitacion.numero}`;
        roomDescriptionEl.textContent = habitacion.descripcion;
        roomPriceEl.textContent = `$${habitacion.precio} MXN`;

        // --- INICIA LÓGICA DE GALERÍA CORREGIDA ---
        if (habitacion.imagen_url && habitacion.imagen_url.length > 0) {
            // 1. Separamos las URLs por PUNTO Y COMA
            const imageUrls = habitacion.imagen_url.split(';'); 

            // 2. Ponemos la primera imagen como la principal
            mainPhotoEl.src = imageUrls[0];
            mainPhotoEl.alt = `Foto principal de ${habitacion.nombre}`;

            // 3. Limpiamos y creamos las miniaturas
            galleryContainer.innerHTML = '';
                imageUrls.slice(0, 4).forEach((url, index) => {
                const img = document.createElement('img');
                img.src = url;
                img.className = 'thumbnail-image';
                img.alt = `Vista ${index + 1} de ${habitacion.nombre}`;

                if (index === 0) {
                    img.classList.add('active');
                }
                img.addEventListener('click', () => {
                    mainPhotoEl.src = url;
                    document.querySelectorAll('.thumbnail-image').forEach(t => t.classList.remove('active'));
                    img.classList.add('active');
                });
                galleryContainer.appendChild(img);
            });
        }

            renderizarServicios(habitacion.servicios);
            calcularPrecioTotal();
        })
        .catch(error => console.error('Error al cargar los detalles:', error));

    // Función para calcular el precio total
    function calcularPrecioTotal() {
        const dateInicio = checkinPicker.selectedDates[0];
        const dateFin = checkoutPicker.selectedDates[0];
        if (dateInicio && dateFin) {
            const diffDias = Math.ceil((dateFin.getTime() - dateInicio.getTime()) / (1000 * 3600 * 24));
            if (diffDias > 0) {
                const total = diffDias * precioPorNoche;
                priceCalculationEl.textContent = `$${precioPorNoche} x ${diffDias} noches`;
                totalPriceEl.textContent = `$${total.toFixed(2)} MXN`;
            } else {
                priceCalculationEl.textContent = 'Fechas inválidas.';
                totalPriceEl.textContent = '';
            }
        } else {
            priceCalculationEl.textContent = 'Selecciona ambas fechas';
            totalPriceEl.textContent = '';
        }
    }

    // Función para mostrar los servicios
    function renderizarServicios(servicios) {
        const iconosServicios = { 'WiFi': 'bi-wifi', 'TV': 'bi-tv', 'Aire acondicionado': 'bi-snow', 'Minibar': 'bi-cup-straw', 'Jacuzzi': 'bi-hot-tub' };
        if (servicios) {
            const listaServicios = servicios.split(', ');
            listaServicios.forEach(servicio => {
                const iconoClase = iconosServicios[servicio] || 'bi-check-lg';
                roomServicesEl.innerHTML += `<div class="service-icon me-3" title="${servicio}"><i class="bi ${iconoClase}"></i><span>${servicio}</span></div>`;
            });
        }
    }
});