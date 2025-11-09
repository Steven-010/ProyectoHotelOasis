// backend/db.js
const mysql = require('mysql2'); // Asumiendo que usas mysql2

// Verifica que el entorno esté en producción (Railway)
// y usa las variables generadas por la plataforma (MYSQL_...)
if (process.env.NODE_ENV === 'production' && process.env.MYSQL_HOST) {
    console.log('Usando configuración de base de datos de Railway (MYSQL_...)');
    
    // Conexión usando las variables de Railway
    const connection = mysql.createConnection({
        // Busca las variables originales de Railway
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        // Usamos OR para cubrir las posibles variables de contraseña
        password: process.env.MYSQL_ROOT_PASSWORD || process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        port: process.env.MYSQL_PORT,
    });

    module.exports = connection;

} else {
    // Conexión usando las variables locales (DB_...) o si falla la anterior
    console.log('Usando configuración de base de datos local (DB_...)');

    const connection = mysql.createConnection({
        // Busca las variables de tu archivo .env local
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'hotel_oasis_db',
        port: process.env.DB_PORT || 3306,
    });
    
    // Verificación de conexión (opcional, pero ayuda a debuggear)
    connection.connect(err => {
        if (err) {
            console.error("Error al conectar a la base de datos local:", err);
            // Si la conexión falla, se detiene la aplicación o se lanza un error
            // throw err; 
        } else {
            console.log("¡Conexión exitosa a la base de datos local!");
        }
    });

    module.exports = connection;
}
