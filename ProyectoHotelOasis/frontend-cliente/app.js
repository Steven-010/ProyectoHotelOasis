document.addEventListener('DOMContentLoaded', () => {

    const fechaInicioInput = document.getElementById('fecha-inicio');
    const fechaFinInput = document.getElementById('fecha-fin');
    const searchButton = document.getElementById('search-button');

    // --- Lógica de Calendarios Conectados ---
    let checkoutPicker; // La declaramos aquí para que sea accesible

    const checkinPicker = flatpickr(fechaInicioInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
        onChange: function (selectedDates, dateStr, instance) {
            // Cuando la fecha de inicio cambia...
            if (selectedDates[0]) {
                // ...le decimos al calendario de salida que su nueva fecha mínima es la de inicio.
                checkoutPicker.set('minDate', selectedDates[0]);

                // Opcional: Si la fecha de salida seleccionada es ahora inválida, la borramos.
                if (checkoutPicker.selectedDates[0] < selectedDates[0]) {
                    checkoutPicker.clear();
                }
            }
            validarFormulario();
        }
    });

    checkoutPicker = flatpickr(fechaFinInput, {
        dateFormat: "Y-m-d",
        minDate: "today",
        altInput: true,
        altFormat: "F j, Y",
        onChange: function () {
            validarFormulario();
        }
    });

    function validarFormulario() {
        const esValido = fechaInicioInput.value && fechaFinInput.value;
        if (searchButton) {
            searchButton.disabled = !esValido;
        }
    }

    // El resto de tu código para el carrusel no cambia...
    cargarHabitacionesPopulares();

    // ... (Pega aquí el resto de tus funciones cargarHabitacionesPopulares y mostrarHabitacionesEnCarrusel) ...
    function cargarHabitacionesPopulares() {
        fetch('http://localhost:4000/api/habitaciones')
            .then(response => response.json())
            .then(habitaciones => {
                mostrarHabitacionesEnCarrusel(habitaciones);
            })
            .catch(error => console.error('Hubo un problema al cargar las habitaciones:', error));
    }

    function mostrarHabitacionesEnCarrusel(habitaciones) {
        const swiperWrapper = document.getElementById('habitaciones-container');
        if (!swiperWrapper) return;
        swiperWrapper.innerHTML = '';
        if (habitaciones.length === 0) {
            swiperWrapper.innerHTML = '<p>No hay habitaciones para mostrar.</p>';
            return;
        }
        habitaciones.forEach(habitacion => {
            const enlace = `habitacion.html?id=${habitacion.id_habitacion}`;
            // --- INICIA CAMBIO ---
            const primeraImagen = habitacion.imagen_url.split(';')[0]; // Tomamos solo la primera URL
            // --- FIN CAMBIO ---
            const slideHTML = `
        <div class="swiper-slide">
            <div class="room-card-v2" style="background-image: url('${primeraImagen}');"> 
                <div class="room-card-v2-overlay">
                    <div class="room-card-v2-content">
                        <h5 class="room-card-v2-title">${habitacion.tipo_nombre}</h5>
                        <p class="room-card-v2-price">$${habitacion.precio} MXN / noche</p>
                        <a href="${enlace}" class="room-card-v2-button">Ver Detalles</a>
                    </div>
                </div>
            </div>
        </div>
        `;
            swiperWrapper.innerHTML += slideHTML;
        });
        
        new Swiper('.room-swiper', {
            loop: true,
            slidesPerView: 1,
            spaceBetween: 30,
            navigation: {
                nextEl: '.swiper-button-next',
                prevEl: '.swiper-button-prev',
            },
            breakpoints: {
                768: { slidesPerView: 2 },
                1200: { slidesPerView: 3 }
            }
        });
    }
});