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
const Curso = require('./models/Curso');
const Curso_Preceptor = require('./models/Curso_Preceptor')
const ResponsableDe = require('./models/ResponsableDe')
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
        const cursos = await Curso.find(); 
        res.render('registerPreceptor', { cursos });
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
        const cursos = await Curso.find();

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
        const { role, dni, password, email, cursoPerteneciente, nroCarnet, ...data } = req.body;

        const existingDniUser = await User.findOne({ dni }).exec();
        if (existingDniUser) {
            return res.status(400).send('El DNI ya está en uso.');
        }

        const existingEmailUser = await User.findOne({ email }).exec();
        if (existingEmailUser) {
            return res.status(400).send('El correo electrónico ya está en uso.');
        }

        let newUser;

        data.username = dni;
        data.email = email;

        switch (role) {
            case 'preceptor':
                newUser = new Preceptor({ ...data, dni });
                break;
            case 'profesor':
                newUser = new Profesor({ ...data, dni });
                break;
            case 'estudiante':
                newUser = new Estudiante({ nroCarnet, dni, cursoPerteneciente, estado: 'pendiente', ...data });
                break;
            case 'responsable':
                newUser = new Responsable({ ...data, dni });
                break;
            case 'directivo':
                newUser = new Directivo({ ...data, dni });
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
            email: email, 
            [`fk_id_${role}`]: newUser._id
        });

        await user.save();

        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.verificationToken = verificationToken;
        await user.save();

        sendVerificationEmail(email, verificationToken);

        res.status(201).send('Registro exitoso. Por favor, verifica tu cuenta por email.');
    } catch (error) {
        console.error('Error:', error);
        res.status(400).send('Error al registrar usuario.');
    }
});

app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    console.log('Token recibido:', token);

    try {
        const user = await User.findOne({ verificationToken: token }).exec();

        if (!user) {
            return res.status(400).send('Token inválido');
        }

        user.isVerified = true;
        user.verificationToken = null; 
        await user.save();

        res.redirect('/login');
    } catch (error) {
        console.error('Error al verificar cuenta:', error);
        res.status(400).send('Error al verificar cuenta.');
    }
});

const loginUser = async (dni, password) => {
    const user = await User.findOne({ dni }).exec();  
    if (!user) {
        throw new Error('Usuario no encontrado');
    }

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
            roleModel = Directivo;
            break;
        default:
            throw new Error('Rol no encontrado');
    }

    const roleUser = await roleModel.findById(user[`fk_id_${user.role}`]).exec();
    if (!roleUser) {
        throw new Error('Usuario correspondiente no encontrado');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        throw new Error('Contraseña incorrecta');
    }

    return { ...roleUser.toObject(), role: user.role };
};

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname + "/loginForm.html"));
});

app.post('/login', async (req, res) => {
    try {
        const { dni, password } = req.body; 
        const user = await loginUser(dni, password);
        const token = jwt.sign({ userId: user._id, role: user.role }, 'tu_secreto', { expiresIn: '1h' });

        res.cookie('token', token, { httpOnly: true });

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
                res.redirect('/directivo-dashboard');
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

app.get('/preceptor-dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptor = await Preceptor.findById(req.user.userId);

        if (!preceptor) {
            return res.status(404).send('Preceptor no encontrado');
        }

        const cursosAsignados = await Curso_Preceptor.find({ fk_id_preceptor: preceptor._id }).populate('fk_id_curso');

        if (preceptor.estado === 'pendiente') {
            res.sendFile(path.join(__dirname, '/esperaDashboard.html')); 
        } else if (preceptor.estado === 'rechazado') {
            res.sendFile(path.join(__dirname, '/rechazadoDashboard.html')); 
        } else if (preceptor.estado === 'aceptado') {
            res.render('preceptorDashboard', { preceptor, cursos: cursosAsignados.map(c => c.fk_id_curso) });
        } else if(preceptor.estado === 'dadobaja') {
            res.sendFile(path.join(__dirname, '/preceptorDadoBaja.html'));
        }else {
            res.status(400).send('Estado de preceptor no válido');
        }

    } catch (error) {
        console.error('Error al redirigir al dashboard del preceptor:', error);
        res.status(500).send('Error interno del servidor');
    }
});


app.get('/profesor-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/profesorDashboard.html'));
});

app.get('/estudiante-dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'estudiante') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiante = await Estudiante.findById(req.user.userId);

        if (!estudiante) {
            return res.status(404).send('Estudiante no encontrado');
        }

        switch (estudiante.estado) {
            case 'pendiente':
                res.sendFile(path.join(__dirname, '/pendienteEstudiante.html'));
                break;
            case 'rechazado':
                res.sendFile(path.join(__dirname, '/rechazadoEstudiante.html'));
                break;
            case 'aceptado':
                res.render('estudianteDashboard', { estudiante });
                break;
            default:
                res.status(400).send('Estado del estudiante no válido');
        }

    } catch (error) {
        console.error('Error al cargar el dashboard del estudiante:', error);
        res.status(500).send('Error interno del servidor');
    }
});

app.get('/responsable-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/responsableDashboard.html'));
});

app.get('/directivo-dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname + '/directivoDashboard.html'));
});

app.get('/preceptores/pendientes', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptoresPendientes = await Preceptor.find({ estado: 'pendiente' });
        res.render('listarPreceptores', { preceptores: preceptoresPendientes });

    } catch (error) {
        console.error('Error al cargar la lista de preceptores:', error);
        res.status(500).send('Error al cargar la lista de preceptores.');
    }
});

app.post('/preceptor/aceptar/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        await Preceptor.findByIdAndUpdate(req.params.id, { estado: 'aceptado' });
        res.redirect('/preceptores/pendientes');

    } catch (error) {
        console.error('Error al aceptar preceptor:', error);
        res.status(500).send('Error al aceptar preceptor.');
    }
});

app.post('/preceptor/rechazar/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        await Preceptor.findByIdAndUpdate(req.params.id, { estado: 'rechazado' });
        res.redirect('/preceptores/pendientes');

    } catch (error) {
        console.error('Error al rechazar preceptor:', error);
        res.status(500).send('Error al rechazar preceptor.');
    }
});

app.get('/preceptores-activos', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptoresActivos = await Preceptor.find({ estado: 'aceptado' });

        res.render('listarPreceptoresActivos', { preceptores: preceptoresActivos });
    } catch (error) {
        console.error('Error al cargar los preceptores activos:', error);
        res.status(500).send('Error al cargar los preceptores activos.');
    }
});

app.post('/dar-baja-preceptor/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptorId = req.params.id;
        await Preceptor.findByIdAndUpdate(preceptorId, { estado: 'dadobaja' });

        res.redirect('/preceptores-activos');
    } catch (error) {
        console.error('Error al dar de baja al preceptor:', error);
        res.status(500).send('Error al dar de baja al preceptor.');
    }
});

app.get('/preceptores-baja', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptoresBaja = await Preceptor.find({ estado: 'dadobaja' });

        res.render('listarPreceptoresBaja', {
            preceptores: preceptoresBaja
        });

    } catch (error) {
        console.error('Error al listar preceptores dados de baja:', error);
        res.status(500).send('Error al listar preceptores dados de baja.');
    }
});

app.post('/dar-alta-preceptor/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptorId = req.params.id;

        await Preceptor.findByIdAndUpdate(preceptorId, { estado: 'aceptado' });

        res.redirect('/preceptores-baja');

    } catch (error) {
        console.error('Error al dar de alta al preceptor:', error);
        res.status(500).send('Error al dar de alta al preceptor.');
    }
});

app.get('/preceptores-rechazados', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptoresRechazados = await Preceptor.find({ estado: 'rechazado' });

        res.render('listarPreceptoresRechazados', { preceptores: preceptoresRechazados });

    } catch (error) {
        console.error('Error al listar preceptores rechazados:', error);
        res.status(500).send('Error al listar preceptores rechazados.');
    }
});

app.post('/aceptar-preceptor-rechazado/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const preceptorId = req.params.id;

        await Preceptor.findByIdAndUpdate(preceptorId, { estado: 'aceptado' });

        res.redirect('/preceptores-rechazados');

    } catch (error) {
        console.error('Error al aceptar preceptor rechazado:', error);
        res.status(500).send('Error al aceptar preceptor rechazado.');
    }
});

app.get('/estudiantes/pendientes/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiantesPendientes = await Estudiante.find({ cursoPerteneciente: req.params.cursoId, estado: 'pendiente' });
        res.render('listarEstudiantesPendientes', { estudiantes: estudiantesPendientes });
    } catch (error) {
        console.error('Error al cargar estudiantes pendientes:', error);
        res.status(500).send('Error al cargar estudiantes pendientes.');
    }
});

app.post('/estudiante/aceptar/:id/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        await Estudiante.findByIdAndUpdate(req.params.id, { estado: 'aceptado' });
        res.redirect('/estudiantes/pendientes/' + req.params.cursoId);
    } catch (error) {
        console.error('Error al aceptar estudiante:', error);
        res.status(500).send('Error al aceptar estudiante.');
    }
});

app.post('/estudiante/rechazar/:id/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        await Estudiante.findByIdAndUpdate(req.params.id, { estado: 'rechazado' });
        res.redirect('/estudiantes/pendientes/' + req.params.cursoId); 
    } catch (error) {
        console.error('Error al rechazar estudiante:', error);
        res.status(500).send('Error al rechazar estudiante.');
    }
});

app.get('/estudiantes-rechazados/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiantesRechazados = await Estudiante.find({ cursoPerteneciente: req.params.cursoId, estado: 'rechazado' });
        res.render('listarEstudiantesRechazados', { estudiantes: estudiantesRechazados });
    } catch (error) {
        console.error('Error al cargar estudiantes rechazados:', error);
        res.status(500).send('Error al cargar estudiantes rechazados.');
    }
});

app.post('/aceptar-estudiante-rechazado/:id/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        await Estudiante.findByIdAndUpdate(req.params.id, { estado: 'aceptado' });
        res.redirect('/estudiantes-rechazados/' + req.params.cursoId);
    } catch (error) {
        console.error('Error al aceptar estudiante rechazado:', error);
        res.status(500).send('Error al aceptar estudiante rechazado.');
    }
});

app.get('/estudiantes-aceptados/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiantesAceptados = await Estudiante.find({ cursoPerteneciente: req.params.cursoId, estado: 'aceptado' });
        res.render('listarEstudiantesAceptados', { estudiantes: estudiantesAceptados });
    } catch (error) {
        console.error('Error al cargar estudiantes aceptados:', error);
        res.status(500).send('Error al cargar estudiantes aceptados.');
    }
});

app.get('/preceptores-cursos', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        const cursoPreceptores = await Curso_Preceptor.find()
            .populate('fk_id_preceptor') 
            .populate('fk_id_curso')  
            .exec();

        res.render('listarPreceptoresCursos', { cursoPreceptores });
    } catch (error) {
        console.error('Error al cargar preceptores y cursos:', error);
        res.status(500).send('Error al cargar la información.');
    }
});

app.post('/eliminar-curso-preceptor/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'directivo') {
            return res.status(403).send('Acceso denegado');
        }

        await Curso_Preceptor.findByIdAndDelete(req.params.id);
        
        res.redirect('/preceptores-cursos');
    } catch (error) {
        console.error('Error al eliminar la asignación de preceptor a curso:', error);
        res.status(500).send('Error al eliminar la asignación.');
    }
});

app.get('/elegir-curso', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const todosLosCursos = await Curso.find();

        const cursosTomados = await Curso_Preceptor.find().distinct('fk_id_curso');

        const cursosDisponibles = todosLosCursos.filter(curso => 
            !cursosTomados.some(cursoTomadoId => cursoTomadoId.equals(curso._id))
        );

        res.render('elegirCurso', {
            user: req.user,
            cursos: cursosDisponibles 
        });

    } catch (error) {
        console.error('Error al cargar la vista de elegir curso:', error);
        res.status(500).send('Error al cargar la vista de elegir curso.');
    }
});

app.post('/elegir-curso', authenticateToken, async (req, res) => {
    try {
        const { cursosSeleccionados } = req.body;

    
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        if (Array.isArray(cursosSeleccionados)) {
            await Promise.all(cursosSeleccionados.map(async (cursoId) => {
                const nuevoCursoPreceptor = new Curso_Preceptor({
                    fk_id_preceptor: req.user.userId,
                    fk_id_curso: cursoId
                });
                await nuevoCursoPreceptor.save();
            }));
        } else {
            const nuevoCursoPreceptor = new Curso_Preceptor({
                fk_id_preceptor: req.user.userId,
                fk_id_curso: cursosSeleccionados
            });
            await nuevoCursoPreceptor.save();
        }

        res.redirect('/preceptor-dashboard');

    } catch (error) {
        console.error('Error al asignar cursos al preceptor:', error);
        res.status(500).send('Error al asignar los cursos.');
    }
});

app.get("/comunicado", authenticateToken, async (req, res) => {
    try {
        let cursos = [];

        if (req.user.role === 'preceptor') {
            cursos = await Curso_Preceptor.find({ fk_id_preceptor: req.user.userId }).populate('fk_id_curso').exec();
        }

        res.render('createComunicado', {
            user: req.user,
            cursos: cursos 
        });
    } catch (error) {
        console.error('Error al cargar la vista de comunicado:', error);
        res.status(400).send('Error al cargar la vista de comunicado.');
    }
});


app.post('/comunicado', authenticateToken, async (req, res) => {
    try {
        const { titulo, info, curso } = req.body;
        
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
        if (req.user.role !== 'estudiante') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiante = await Estudiante.findById(req.user.userId).exec();
        
        const comunicados = await Comunicado.find({
            $or: [
                { general: true },  
                { curso: estudiante.cursoPerteneciente } 
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