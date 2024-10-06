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
const Curso = require('./models/Curso'); // Asegúrate de importar el modelo de Curso
const Curso_Preceptor = require('./models/Curso_Preceptor')
const router = express.Router();
connectDB();
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

router.get('/register/preceptor', async (req, res) => {
    try {
        const cursos = await Curso.find(); // Obtener todos los cursos
        res.render('registerPreceptor', { cursos }); // Pasar los cursos a la vista
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).send('Error al cargar el formulario.');
    }
});

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

app.get('/register', async (req, res) => {
    const { role } = req.query;

    try {
        const cursos = await Curso.find(); // Obtener todos los cursos para los formularios que lo requieran

        switch (role) {
            case 'preceptor':
                res.render('registerPreceptor', { cursos });
                break;
            case 'profesor':
                res.render('registerProfesor', { cursos });
                break;
            case 'estudiante':
                res.render('registerEstudiante', { cursos });
                break;
            case 'responsable':
                res.render('registerResponsable', { cursos });
                break;
            case 'directivo':
                res.render('registerDirectivo', { cursos });
                break;
            default:
                res.status(400).send('Rol no reconocido');
        }
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).send('Error al cargar el formulario de registro.');
    }
});

app.post('/register', async (req, res) => {
    try {
        const { role, dni, password, email, nroCarnet, ...data } = req.body;

        // Verificar si el DNI ya está en uso
        const existingDniUser = await User.findOne({ dni }).exec();
        if (existingDniUser) {
            return res.status(400).send('El DNI ya está en uso.');
        }

        // Verificar si el correo electrónico ya está en uso
        const existingEmailUser = await User.findOne({ email }).exec();
        if (existingEmailUser) {
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

async function obtenerCursoDePreceptor(preceptorId) {
    const preceptor = await Preceptor.findById(preceptorId).populate('cursoACargo').exec();
    if (!preceptor) {
        throw new Error('Preceptor no encontrado');
    }
    return preceptor.cursoACargo; // Asegúrate de que esto devuelva un objeto de curso completo
}


app.get("/comunicado", authenticateToken, async (req, res) => {
    try {
        let cursos = [];
        
        // Si el usuario es preceptor, obtener su curso
        if (req.user.role === 'preceptor') {
            const cursoId = await obtenerCursoDePreceptor(req.user.userId);
            cursos.push(cursoId);  // Agrega solo el ObjectId
        }

        res.render('createComunicado', {
            user: req.user,
            cursos: cursos // Esto debe ser un array de ObjectIds
        });
    } catch (error) {
        console.error('Error al cargar la vista de comunicado:', error);
        res.status(400).send('Error al cargar la vista de comunicado.');
    }
});

app.post('/comunicado', authenticateToken, async (req, res) => {
    try {
        const { titulo, info, curso } = req.body;
        
        // Agrega este console.log para ver el valor de curso
        console.log('ID del curso recibido:', curso);

        let comunicado;

        if (req.user.role === 'directivo') {
            comunicado = new Comunicado({
                titulo,
                info,
                general: true,
                fk_id_directivo: req.user.userId
            });

        } else if (req.user.role === 'preceptor') {
            // Verifica si el curso es válido
            if (!curso || !mongoose.Types.ObjectId.isValid(curso)) {
                return res.status(400).send('Debe seleccionar un curso válido para enviar el comunicado.');
            }

            comunicado = new Comunicado({
                titulo,
                info,
                curso,
                general: false,
                fk_id_preceptor: req.user.userId
            });
        } else {
            return res.status(403).send('Acceso denegado');
        }

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
                    <a href="/${req.user.role}-dashboard" class="btn">Ir a mi inicio</a>
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
        // Verificar que el usuario es un estudiante
        if (req.user.role !== 'estudiante') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiante = await Estudiante.findById(req.user.userId).exec();
        
        // Buscar comunicados generales o específicos de su curso
        const comunicados = await Comunicado.find({
            $or: [
                { general: true },  // Comunicado general
                { curso: estudiante.cursoPerteneciente }  // Comunicado dirigido a su curso
            ]
        }).populate('fk_id_preceptor').exec();

        res.status(200).json(comunicados);
    } catch (error) {
        console.error('Error al obtener comunicados:', error);
        res.status(400).send('Error al obtener comunicados');
    }
});

app.listen(3000, () => {
    console.log('Servidor escuchando en http://localhost:3000');
});