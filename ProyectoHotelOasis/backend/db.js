const mysql = require('mysql2');

// Crea el "puente" de conexión con tus credenciales
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root', // tu usuario MySQL
    password: '16Di1983', // tu contraseña MySQL
    database: 'hotel_oasis_db'
});


// Verificamos si la conexión funciona
connection.connect(error => {
    if (error) {
        console.error('Error al conectar a la base de datos:', error);
        return;
    }
    console.log('¡Conexión exitosa a la base de datos!');
});

module.exports = connection;