document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const roomId = params.get('id');
    const fechaInicio = params.get('inicio');
    const fechaFin = params.get('fin');
    const huespedes = params.get('huespedes');

    const summaryDetailsEl = document.getElementById('summary-details');
    const summaryRoomNameEl = document.getElementById('summary-room-name');
    const summaryRoomPhotoEl = document.getElementById('summary-room-photo');
    const customerForm = document.getElementById('customer-form');
    const creditCardForm = document.getElementById('credit-card-form');
    const confirmButton = document.getElementById('confirm-button');
    
    // --- ESTA ES LA LÓGICA CORREGIDA ---
    document.querySelectorAll('input[name="paymentMethod"]').forEach(radio => {
        radio.addEventListener('change', (event) => {
            if (event.target.id === 'tarjeta') {
                // Si se selecciona 'tarjeta', quitamos la clase que oculta el formulario
                creditCardForm.classList.remove('d-none');
            } else {
                // Si se selecciona cualquier otra cosa (efectivo), añadimos la clase para ocultarlo
                creditCardForm.classList.add('d-none');
            }
        });
    });

    // El resto de tu código para cargar el resumen y enviar el formulario no cambia
    fetch(`http://localhost:4000/api/habitaciones/${roomId}`)
        .then(response => response.json())
        .then(habitacion => {
            summaryRoomNameEl.textContent = `${habitacion.nombre} #${habitacion.numero}`;
            summaryRoomPhotoEl.src = 'https://images.unsplash.com/photo-1566665797739-1674de7a421a?q=80&w=1974';

            const dateInicio = new Date(fechaInicio);
            const dateFin = new Date(fechaFin);
            const diffDias = Math.ceil((dateFin.getTime() - dateInicio.getTime()) / (1000 * 3600 * 24));
            const total = diffDias * habitacion.precio;

            summaryDetailsEl.innerHTML = `
                <div class="summary-details-item">
                    <span><i class="bi bi-box-arrow-in-right me-2"></i>Check-in:</span>
                    <strong class="fw-bold">${fechaInicio}</strong>
                </div>
                <div class="summary-details-item">
                    <span><i class="bi bi-box-arrow-left me-2"></i>Check-out:</span>
                    <strong class="fw-bold">${fechaFin}</strong>
                </div>
                <div class="summary-details-item">
                    <span><i class="bi bi-people me-2"></i>Huéspedes:</span>
                    <strong class="fw-bold">${huespedes}</strong>
                </div>
                <hr>
                <div class="summary-details-item fs-4">
                    <span>Total:</span>
                    <strong class="text-primary">$${total.toFixed(2)} MXN</strong>
                </div>
            `;
        });

    customerForm.addEventListener('submit', (event) => {
        event.preventDefault();
        confirmButton.disabled = true;
        const metodoPago = document.querySelector('input[name="paymentMethod"]:checked').id;

        if (metodoPago === 'tarjeta') {
            confirmButton.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Procesando...';
            setTimeout(() => {
                const ccNumber = document.getElementById('cc-number').value;
                if (ccNumber === '4242 4242 4242 4242') {
                    enviarReservaAlBackend();
                } else {
                    alert('Pago fallido. Verifica los datos.');
                    confirmButton.disabled = false;
                    confirmButton.innerHTML = 'Confirmar y Pagar';
                }
            }, 2000);
        } else {
            confirmButton.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Confirmando...';
            enviarReservaAlBackend();
        }
    });

    function enviarReservaAlBackend() {
        const cliente = {
            nombre: document.getElementById('nombre').value,
            apellido: document.getElementById('apellido').value,
            email: document.getElementById('email').value,
            telefono: document.getElementById('telefono').value
        };
        const datosReserva = {
            id_habitacion: roomId, fecha_inicio: fechaInicio, fecha_fin: fechaFin,
            num_huespedes: huespedes, cliente: cliente
        };

        fetch('http://localhost:4000/api/reservas', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(datosReserva),
        })
        .then(response => response.json())
        .then(data => {
            if (data.codigo) {
                window.location.href = `exito.html?codigo=${data.codigo}`;
            } else {
                throw new Error(data.mensaje || 'Error desconocido');
            }
        })
        .catch(error => {
            console.error('Error al crear la reserva:', error);
            alert('Hubo un error al confirmar tu reserva. Intenta de nuevo.');
            confirmButton.disabled = false;
            confirmButton.innerHTML = 'Confirmar y Pagar';
        });
    }
});