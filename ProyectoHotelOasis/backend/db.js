const mysql = require('mysql2');

// Crea el "puente" de conexión utilizando las variables de entorno de Railway
const connection = mysql.createConnection({
    // Usa la variable HOST que configuraste en Railway
    host: process.env.HOST, 
    
    // Usa la variable USER que configuraste en Railway
    user: process.env.USER, 
    
    // Usa la variable PASSWORD que configuraste en Railway
    password: process.env.PASSWORD, 
    
    // Usa la variable DATABASE que configuraste en Railway
    database: process.env.DATABASE
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
