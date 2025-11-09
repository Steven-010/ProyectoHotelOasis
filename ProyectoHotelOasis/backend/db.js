const mysql = require('mysql2');

// Crea la conexión usando las variables correctas de Railway
const connection = mysql.createConnection({
    host: process.env.DB_HOST,       // mysql.railway.internal
    user: process.env.DB_USER,       // root
    password: process.env.DB_PASSWORD, // tu contraseña de railway
    database: process.env.DB_NAME,     // ferrocarril
    port: process.env.DB_PORT        // 3306
});

// Verificamos si la conexión funciona
connection.connect(error => {
    if (error) {
        console.error(' Error al conectar a la base de datos:', error);
        return;
    }
    console.log(' ¡Conexión exitosa a la base de datos en Railway!');
});

module.exports = connection;