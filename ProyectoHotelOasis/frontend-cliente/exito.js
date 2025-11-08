//=============== exito.js (VERSIÓN CORREGIDA) ===============

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const codigoReserva = params.get('codigo');
    const ticketDetailsEl = document.getElementById('ticket-details');

    if (!codigoReserva) {
        ticketDetailsEl.innerHTML = '<p class="text-danger">No se especificó un código de reserva.</p>';
        return;
    }

    fetch(`http://localhost:4000/api/reservas/${codigoReserva}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Reserva no encontrada.');
            }
            return response.json();
        })
        .then(reserva => {
            const dateInicio = new Date(reserva.fecha_inicio);
            const dateFin = new Date(reserva.fecha_fin);
            const diffDias = Math.ceil((dateFin.getTime() - dateInicio.getTime()) / (1000 * 3600 * 24));
            
            // --- ¡ESTA ES LA LÍNEA CORREGIDA! ---
            // Usamos parseFloat() para convertir el texto a número ANTES de usar .toFixed()
            const precioNoche = parseFloat(reserva.precio_por_noche);
            const total = diffDias * precioNoche;

            ticketDetailsEl.innerHTML = `
                <div class="ticket-item"><span>Código de Reserva:</span><strong>${reserva.codigo_reserva}</strong></div>
                <hr>
                <div class="ticket-item"><span>Cliente:</span><strong>${reserva.nombre} ${reserva.apellido}</strong></div>
                <div class="ticket-item"><span>Habitación:</span><strong>${reserva.tipo_nombre} #${reserva.numero}</strong></div>
                <div class="ticket-item"><span>Check-in:</span><strong>${dateInicio.toLocaleDateString()}</strong></div>
                <div class="ticket-item"><span>Check-out:</span><strong>${dateFin.toLocaleDateString()}</strong></div>
                <div class="ticket-item"><span>Huéspedes:</span><strong>${reserva.num_huespedes}</strong></div>
                <hr>
                <div class="ticket-item text-muted"><span>Costo por noche:</span><span>$${precioNoche.toFixed(2)} MXN x ${diffDias} noches</span></div>
                <div class="ticket-item fs-4"><strong>Total a Pagar:</strong><strong class="text-primary">$${total.toFixed(2)} MXN</strong></div>
                <hr>
                <p class="mt-3 text-muted">Presenta este código al momento de tu check-in. ¡Gracias por tu preferencia!</p>
            `;
        })
        .catch(error => {
            console.error('Error al cargar los detalles de la reserva:', error);
            ticketDetailsEl.innerHTML = '<p class="text-danger">No se pudieron cargar los detalles de tu reserva.</p>';
        });
});