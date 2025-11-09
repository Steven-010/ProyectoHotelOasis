const express = require('express');
const app = express();
const port = process.env.PORT || 4000; // <-- CAMBIADO PARA RAILWAY

// 1. CARGA DE VARIABLES DE ENTORNO
require('dotenv').config();

// 2. MIDDLEWARE Y PAQUETES
const bcrypt = require('bcryptjs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const db = require('./db.js');

// Configuración de Express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuración de la sesión
app.use(session({
    secret: process.env.SESSION_SECRET || 'otra_llave_secreta_para_la_sesion',
    resave: false,
    saveUninitialized: true
}));

// Inicializa Passport
app.use(passport.initialize());
app.use(passport.session());

// Serializar/Deserializar usuario
passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((user, done) => {
    done(null, user);
});

// 3. GOOGLE LOGIN
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.CALLBACK_URL_BASE}/api/auth/google/callback`
},
(accessToken, refreshToken, profile, done) => {
    db.query(`SELECT * FROM clientes WHERE google_id = ?`, [profile.id], (err, results) => {
        if (err) return done(err);

        if (results.length > 0) {
            return done(null, results[0]);
        } else {
            const nuevoCliente = {
                nombre: profile.name.givenName,
                apellido: profile.name.familyName,
                email: profile.emails[0].value,
                google_id: profile.id,
                contrasena: 'google-provided'
            };
            
            db.query(`INSERT INTO clientes SET ?`, [nuevoCliente], (err, insertResult) => {
                if (err) return done(err);
                nuevoCliente.id = insertResult.insertId;
                return done(null, nuevoCliente);
            });
        }
    });
}));

// 4. FACEBOOK LOGIN
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: `${process.env.CALLBACK_URL_BASE}/api/auth/facebook/callback`,
    profileFields: ['id', 'displayName', 'emails']
},
(accessToken, refreshToken, profile, done) => {
    db.query(`SELECT * FROM clientes WHERE facebook_id = ?`, [profile.id], (err, results) => {
        if (err) return done(err);

        if (results.length > 0) {
            return done(null, results[0]);
        } else {
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
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => { res.redirect('/perfil'); }
);

app.get('/api/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/api/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    (req, res) => { res.redirect('/perfil'); }
);

// LOGIN NORMAL
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    db.query(`SELECT * FROM clientes WHERE email = ?`, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Error interno del servidor' });
        if (results.length === 0) return res.status(401).json({ message: 'Credenciales inválidas.' });

        const user = results[0];

        if (user.contrasena === 'google-provided' || user.contrasena === 'facebook-provided') {
            return res.status(401).json({ message: 'Usa el inicio de sesión social.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.contrasena);

        if (passwordMatch) {
            const jwt = require('jsonwebtoken');
            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

            return res.status(200).json({ 
                message: 'Login exitoso', 
                token,
                user: { id: user.id, email: user.email, nombre: user.nombre } 
            });
        } else {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }
    });
});

// REGISTER
app.post('/api/auth/register', async (req, res) => {
    const { nombre, apellido, email, password } = req.body;

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const nuevoCliente = { nombre, apellido, email, contrasena: hashedPassword };

        db.query(`INSERT INTO clientes SET ?`, [nuevoCliente], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'El correo ya está registrado.' });
                }
                return res.status(500).json({ error: 'Error al registrar el usuario' });
            }

            res.status(201).json({ message: 'Usuario registrado exitosamente', id: result.insertId });
        });

    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 7. INICIO DEL SERVIDOR
app.listen(port, () => {
    console.log(` Servidor de Hotel Oasis corriendo en http://localhost:${port}`);
});
