const express = require('express');
const app = express();
const port = 4000;

// 1. CARGA DE VARIABLES DE ENTORNO (¡NUEVO!)
require('dotenv').config();

// 2. MIDDLEWARE Y PAQUETES
const bcrypt = require('bcryptjs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const db = require('./db.js'); // Asume que tienes un archivo db.js para la conexión

// Configuración de Express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuración de la sesión
app.use(session({
    // Utiliza la variable de entorno, si no existe, usa un valor por defecto.
    secret: process.env.SESSION_SECRET || 'otra_llave_secreta_para_la_sesion',
    resave: false,
    saveUninitialized: true
}));

// Inicializa Passport
app.use(passport.initialize());
app.use(passport.session());

// Función de serialización/deserialización de usuario (MANTENER)
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// 3. CONFIGURACIÓN DE PASSPORT PARA GOOGLE (¡MODIFICADO!)
passport.use(new GoogleStrategy({
    // ¡IMPORTANTE! Las credenciales ahora vienen del archivo .env
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.CALLBACK_URL_BASE}/api/auth/google/callback` // Usa la URL base del .env
},
(accessToken, refreshToken, profile, done) => {
    // Lógica para buscar/crear usuario en la base de datos
    db.query(`SELECT * FROM clientes WHERE google_id = ?`, [profile.id], (err, results) => {
        if (err) return done(err);

        if (results.length > 0) {
            // Usuario encontrado, retornar el usuario
            return done(null, results[0]);
        } else {
            // Usuario no encontrado, crearlo
            const nuevoCliente = {
                nombre: profile.name.givenName,
                apellido: profile.name.familyName,
                email: profile.emails[0].value,
                google_id: profile.id,
                contrasena: 'google-provided' // Marcar como usuario de Google
            };
            
            db.query(`INSERT INTO clientes SET ?`, [nuevoCliente], (err, insertResult) => {
                if (err) return done(err);
                
                // Obtener el ID del nuevo cliente para devolver el objeto completo
                nuevoCliente.id = insertResult.insertId; 
                return done(null, nuevoCliente);
            });
        }
    });
}));

// 4. CONFIGURACIÓN DE PASSPORT PARA FACEBOOK (¡MODIFICADO!)
passport.use(new FacebookStrategy({
    // ¡IMPORTANTE! Las credenciales ahora vienen del archivo .env
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: `${process.env.CALLBACK_URL_BASE}/api/auth/facebook/callback`, // Usa la URL base del .env
    profileFields: ['id', 'displayName', 'emails'] // Campos que queremos del perfil
},
(accessToken, refreshToken, profile, done) => {
    // Lógica para buscar/crear usuario en la base de datos (similar a Google)
    db.query(`SELECT * FROM clientes WHERE facebook_id = ?`, [profile.id], (err, results) => {
        if (err) return done(err);

        if (results.length > 0) {
            // Usuario encontrado, retornar el usuario
            return done(null, results[0]);
        } else {
            // Usuario no encontrado, crearlo
            const nuevoCliente = {
                nombre: profile.displayName.split(' ')[0] || 'Facebook',
                apellido: profile.displayName.split(' ')[1] || 'User',
                email: profile.emails ? profile.emails[0].value : null,
                facebook_id: profile.id,
                contrasena: 'facebook-provided'
            };
            
            db.query(`INSERT INTO clientes SET ?`, [nuevoCliente], (err, insertResult) => {
                if (err) return done(err);
                
                nuevoCliente.id = insertResult.insertId;
                return done(null, nuevoCliente);
            });
        }
    });
}));


// 5. RUTAS DE AUTENTICACIÓN
// Ruta de inicio de sesión de Google
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Ruta de callback de Google (donde Google redirige después de la autenticación)
app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }), // Redirigir a /login en caso de fallo
    (req, res) => {
        // Autenticación exitosa, redirigir al perfil o a donde corresponda
        res.redirect('/perfil'); 
    }
);

// Ruta de inicio de sesión de Facebook
app.get('/api/auth/facebook',
    passport.authenticate('facebook', { scope: ['email'] })
);

// Ruta de callback de Facebook
app.get('/api/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    (req, res) => {
        // Autenticación exitosa, redirigir
        res.redirect('/perfil'); 
    }
);


// 6. OTRAS RUTAS (Ejemplo de login y registro normal)

// Ruta de Login normal con Email/Contraseña
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    db.query(`SELECT * FROM clientes WHERE email = ?`, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Error interno del servidor' });
        if (results.length === 0) return res.status(401).json({ message: 'Credenciales inválidas.' });

        const user = results[0];

        // Nota: Si el usuario fue creado por OAuth, no tiene un hash bcrypt.
        if (user.contrasena === 'google-provided' || user.contrasena === 'facebook-provided') {
            return res.status(401).json({ message: 'Por favor, usa el inicio de sesión de Google/Facebook.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.contrasena);

        if (passwordMatch) {
            // Login exitoso
            // Aquí deberías generar un JWT (JSON Web Token) y enviarlo al cliente
            // Usando la variable secreta del .env
            const jwt = require('jsonwebtoken');
            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

            return res.status(200).json({ 
                message: 'Login exitoso', 
                token: token,
                user: { id: user.id, email: user.email, nombre: user.nombre } 
            });
        } else {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }
    });
});

// Ruta para Registrar un nuevo usuario (Ejemplo)
app.post('/api/auth/register', async (req, res) => {
    const { nombre, apellido, email, password } = req.body;

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const nuevoCliente = { 
            nombre, 
            apellido, 
            email, 
            contrasena: hashedPassword 
        };

        db.query(`INSERT INTO clientes SET ?`, [nuevoCliente], (err, result) => {
            if (err) {
                // Error 1062 es duplicado (email ya existe)
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'El correo ya está registrado.' });
                }
                console.error(err);
                return res.status(500).json({ error: 'Error al registrar el usuario' });
            }

            res.status(201).json({ 
                message: 'Usuario registrado exitosamente', 
                id: result.insertId 
            });
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// 7. INICIO DEL SERVIDOR
app.listen(port, () => {
    console.log(`Servidor de Hotel Oasis corriendo en http://localhost:${port}`);
});