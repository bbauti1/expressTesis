const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require("path");
const cookieParser = require('cookie-parser');
const sendVerificationEmail = require('./mailService');

const User = require('./models/User');
const connectDB = require('./db');
const Responsable = require('./models/Responsable');
const Estudiante = require('./models/Estudiante');
const Preceptor = require('./models/Preceptor');
const Profesor = require('./models/Profesor');
const Comunicado = require('./models/Comunicado');
const Directivo = require('./models/Directivo');

connectDB();
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cookieParser());

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }

    jwt.verify(token, 'tu_secreto', (err, user) => {
        if (err) {
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname + "/index.html"));
});

app.get("/select-role", (req, res) => {
    res.sendFile(path.join(__dirname + "/selectRole.html"));
});

app.get('/register', (req, res) => {
    const { role } = req.query;

    switch (role) {
        case 'preceptor':
            res.sendFile(path.join(__dirname, 'registerPreceptor.html'));
            break;
        case 'profesor':
            res.sendFile(path.join(__dirname, 'registerProfesor.html'));
            break;
        case 'estudiante':
            res.sendFile(path.join(__dirname, 'registerEstudiante.html'));
            break;
        case 'responsable':
            res.sendFile(path.join(__dirname, 'registerResponsable.html'));
            break;
        case 'directivo':
            res.sendFile(path.join(__dirname, 'registerDirectivo.html')); // Asegúrate de que esta línea sea correcta
            break;
        default:
            res.status(400).send('Rol no reconocido');
    }
});

app.post('/register', async (req, res) => {
    try {
        const { role, dni, password, email, nroCarnet, ...data } = req.body;

        // Verificar si el correo electrónico ya está en uso
        const existingUser = await User.findOne({ email }).exec();
        if (existingUser) {
            return res.status(400).send('El correo electrónico ya está en uso.');
        }

        let newUser;

        // Asegúrate de que los campos username y email se incluyan correctamente
        data.username = dni;
        data.email = email;

        // Crear un nuevo usuario basado en el rol
        switch (role) {
            case 'preceptor':
                newUser = new Preceptor({ ...data, dni });
                break;
            case 'profesor':
                newUser = new Profesor({ ...data, dni });
                break;
            case 'estudiante':
                newUser = new Estudiante({ nroCarnet, dni, ...data });
                break;
            case 'responsable':
                newUser = new Responsable({ ...data, dni });
                break;
            case 'directivo': // Asegúrate de que este caso esté incluido
                newUser = new Directivo({ ...data, dni }); // Aquí es donde utilizas data
                break;
            default:
                return res.status(400).send('Rol no reconocido');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        newUser.password = hashedPassword;

        await newUser.save();

        const user = new User({
            dni: dni,
            password: hashedPassword,
            role: role,
            email: email,  // Guardar email
            [`fk_id_${role}`]: newUser._id
        });

        await user.save();

        // Generar token de verificación
        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.verificationToken = verificationToken;
        await user.save();

        // Enviar correo de verificación
        sendVerificationEmail(email, verificationToken);

        res.status(201).send('Registro exitoso. Por favor, verifica tu cuenta por email.');
    } catch (error) {
        console.error('Error:', error);
        res.status(400).send('Error al registrar usuario.');
    }
});

app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    console.log('Token recibido:', token); // Debugging

    try {
        const user = await User.findOne({ verificationToken: token }).exec();

        if (!user) {
            return res.status(400).send('Token inválido');
        }

        user.isVerified = true;
        user.verificationToken = null;  // Eliminar el token una vez verificado
        await user.save();

        res.redirect('/login');
    } catch (error) {
        console.error('Error al verificar cuenta:', error);
        res.status(400).send('Error al verificar cuenta.');
    }
});

const loginUser = async (dni, password) => {
    // Buscar al usuario por DNI
    const user = await User.findOne({ dni }).exec();  
    if (!user) {
        throw new Error('Usuario no encontrado');
    }

    // Verificar si el usuario ha verificado su cuenta
    if (!user.isVerified) {
        throw new Error('Por favor, verifica tu email antes de iniciar sesión.');
    }

    let roleModel;
    switch (user.role) {
        case 'preceptor':
            roleModel = Preceptor;
            break;
        case 'profesor':
            roleModel = Profesor;
            break;
        case 'estudiante':
            roleModel = Estudiante;
            break;
        case 'responsable':
            roleModel = Responsable;
            break;
        case 'directivo':
            roleModel = Directivo; // Asignar el modelo Directivo
            break;
        default:
            throw new Error('Rol no encontrado');
    }

    // Buscar el usuario del rol correspondiente
    const roleUser = await roleModel.findById(user[`fk_id_${user.role}`]).exec();
    if (!roleUser) {
        throw new Error('Usuario correspondiente no encontrado');
    }

    // Verificar si la contraseña es correcta
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        throw new Error('Contraseña incorrecta');
    }

    // Retornar la información del usuario
    return { ...roleUser.toObject(), role: user.role };
};

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname + "/loginForm.html"));
});

app.post('/login', async (req, res) => {
    try {
        const { dni, password } = req.body;  // Ahora usa DNI
        const user = await loginUser(dni, password);  // Inicia sesión con DNI
        const token = jwt.sign({ userId: user._id, role: user.role }, 'tu_secreto', { expiresIn: '1h' });

        res.cookie('token', token, { httpOnly: true });

        // Redirigir al dashboard correspondiente según el rol
        switch (user.role) {
            case 'preceptor':
                res.redirect('/preceptor-dashboard');
                break;
            case 'profesor':
                res.redirect('/profesor-dashboard');
                break;
            case 'estudiante':
                res.redirect('/estudiante-dashboard');
                break;
            case 'responsable':
                res.redirect('/responsable-dashboard');
                break;
            case 'directivo':
                res.redirect('/directivo-dashboard'); // Redirigir a dashboard del Directivo
                break;
            default:
                res.status(400).send('Rol no reconocido');
        }
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(400).send('Error al iniciar sesión.');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

app.get('/preceptor-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/preceptorDashboard.html'));
});

app.get('/profesor-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/profesorDashboard.html'));
});

app.get('/estudiante-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/estudianteDashboard.html'));
});

app.get('/responsable-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/responsableDashboard.html'));
});

app.get('/directivo-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/directivoDashboard.html'));
});

app.get("/comunicado", (req, res) => {
    res.sendFile(path.join(__dirname + "/createComunicado.html"));
});

app.post('/comunicado', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const { titulo, info, curso } = req.body;

        const comunicado = new Comunicado({
            titulo,
            info,
            curso,
            fk_id_preceptor: req.user.userId
        });

        await comunicado.save();
        res.status(201).send(`
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel="stylesheet" href="/css/style.css">
                <title>Comunicado Creado</title>
            </head>
            <body>
                <div class="message-container">
                    <h1>Comunicado creado con éxito</h1>
                    <a href="/preceptor-dashboard" class="btn">Ir a mi inicio</a>
                </div>
            </body>
            </html>
        `);
        
    } catch (error) {
        console.error('Error al crear comunicado:', error);
        res.status(400).send('Error al crear comunicado');
    }
});

app.get('/comunicados', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'estudiante') {
            return res.status(403).send('Acceso denegado');
        }

        res.sendFile(path.join(__dirname, 'verComunicados.html'));
    } catch (error) {
        console.error('Error al obtener comunicados:', error);
        res.status(400).send('Error al obtener comunicados');
    }
});

app.get('/api/comunicados-data', authenticateToken, async (req, res) => {
    try {
        const estudiante = await Estudiante.findById(req.user.userId).exec();
        const comunicados = await Comunicado.find({ curso: estudiante.cursoPerteneciente }).populate('fk_id_preceptor').exec();
        res.status(200).json(comunicados);
    } catch (error) {
        console.error('Error al obtener comunicados:', error);
        res.status(400).send('Error al obtener comunicados');
    }
});


app.listen(3000, () => {
    console.log('Servidor escuchando en http://localhost:3000');
});