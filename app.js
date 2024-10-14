const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require("path");
const cookieParser = require('cookie-parser');
const sendVerificationEmail = require('./mailService');
const multer = require('multer');

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
app.use('/uploads', express.static('public/uploads'));

router.get('/register/preceptor', async (req, res) => {
    try {
        const cursos = await Curso.find(); 
        res.render('registerPreceptor', { cursos });
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).send('Error al cargar el formulario.');
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './public/uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage: storage });

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
        console.log(req.user)
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
                newUser = new Directivo({ ...data, dni , estadoSolicitud: 'pendiente'});
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
    console.log("Buscando usuario con dni:", dni);
    const user = await User.findOne({ dni }).exec();
    console.log("Usuario encontrado:", user);
    console.log(user);   
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
        case 'admin':
            return { role: 'admin' };
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
            case 'admin':  // Redirige al dashboard de admin
                res.redirect('/admin-dashboard');
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
            case 'dadobaja':
                res.sendFile(path.join(__dirname, '/dadoBajaEstudiante.html'));
                break;
            default:
                res.status(400).send('Estado del estudiante no válido');
        }

    } catch (error) {
        console.error('Error al cargar el dashboard del estudiante:', error);
        res.status(500).send('Error interno del servidor');
    }
});

app.get('/responsable-dashboard', authenticateToken, async (req, res) => {
    if (req.user.role !== 'responsable') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const solicitudesPendientes = await ResponsableDe.find({
            fk_id_responsable: req.user.userId,
            estadoSolicitud: 'pendiente'
        }).populate('fk_id_estudiante');

        const solicitudesRechazadas = await ResponsableDe.find({
            fk_id_responsable: req.user.userId,
            estadoSolicitud: 'rechazado'
        }).populate('fk_id_estudiante');

        const estudiantesACargo = await ResponsableDe.find({
            fk_id_responsable: req.user.userId,
            estadoSolicitud: 'aceptado'
        }).populate({
            path: 'fk_id_estudiante',
            populate: { path: 'cursoPerteneciente' }
        });

        const solicitudesDadoBaja = await ResponsableDe.find({
            fk_id_responsable: req.user.userId,
            estadoSolicitud: 'dadobaja'
        }).populate({
            path: 'fk_id_estudiante',
            populate: { path: 'cursoPerteneciente' }
        });

        res.render('responsableDashboard', {
            responsable: req.user, 
            solicitudesPendientes: solicitudesPendientes,
            solicitudesRechazadas: solicitudesRechazadas,
            estudiantesACargo: estudiantesACargo.map(relacion => relacion.fk_id_estudiante),
            solicitudesDadoBaja: solicitudesDadoBaja.map(relacion => relacion.fk_id_estudiante)
        });
    } catch (error) {
        console.error('Error al cargar el dashboard del responsable:', error);
        res.status(500).send('Error al cargar el dashboard');
    }
});

app.get('/directivo-dashboard', authenticateToken, async (req, res) => {
    if (req.user.role !== 'directivo') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        // Encontrar el directivo en la base de datos usando su id
        const directivo = await Directivo.findById(req.user.userId);

        // Redirigir a diferentes dashboards según el estado de la solicitud
        switch (directivo.estadoSolicitud) {
            case 'pendiente':
                return res.render('directivoPendiente', { directivo });
            case 'rechazado':
                return res.render('directivoRechazado', { directivo });
            case 'dadobaja':
                return res.render('directivoDadoBaja', { directivo });
            case 'aceptado':
                return res.sendFile(path.join(__dirname + '/directivoDashboard.html'));
            default:
                return res.status(400).send('Estado de solicitud no válido');
        }
    } catch (error) {
        console.error('Error al cargar el dashboard del directivo:', error);
        res.status(500).send('Error al cargar el dashboard del directivo');
    }
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

app.post('/dar-baja-estudiante/:id/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        await Estudiante.findByIdAndUpdate(req.params.id, { estado: 'dadobaja' });

        res.redirect(`/estudiantes-aceptados/${req.params.cursoId}`);
    } catch (error) {
        console.error('Error al dar de baja al estudiante:', error);
        res.status(500).send('Error al dar de baja al estudiante.');
    }
});

app.get('/estudiantes-baja/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const estudiantesBaja = await Estudiante.find({ cursoPerteneciente: req.params.cursoId, estado: 'dadobaja' });
        res.render('listarEstudiantesBaja', { estudiantes: estudiantesBaja });
    } catch (error) {
        console.error('Error al cargar estudiantes dados de baja:', error);
        res.status(500).send('Error al cargar estudiantes dados de baja.');
    }
});

app.post('/dar-alta-estudiante/:id/:cursoId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        await Estudiante.findByIdAndUpdate(req.params.id, { estado: 'aceptado' });

        res.redirect(`/estudiantes-baja/${req.params.cursoId}`);
    } catch (error) {
        console.error('Error al dar de alta al estudiante:', error);
        res.status(500).send('Error al dar de alta al estudiante.');
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

app.get('/add-student', authenticateToken, async (req, res) => {
    if (req.user.role !== 'responsable') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const cursos = await Curso.find(); 
        res.render('addStudent', { cursos });  
    } catch (error) {
        console.error('Error al obtener cursos:', error);
        res.status(500).send('Error al cargar el formulario.');
    }
});

app.post('/add-student', authenticateToken, async (req, res) => {
    if (req.user.role !== 'responsable') {
        return res.status(403).send('Acceso denegado');
    }

    const { dni, nombre, apellido, email, curso } = req.body;

    try {
        const estudianteExistente = await Estudiante.findOne({ dni, nombre, apellido, email, cursoPerteneciente: curso });
        
        if (!estudianteExistente) {
            return res.status(404).send('Estudiante no encontrado');
        }

        const relacionExistente = await ResponsableDe.findOne({
            fk_id_estudiante: estudianteExistente._id,
            fk_id_responsable: req.user.userId
        });

        if (relacionExistente) {
            return res.status(400).send('El estudiante ya está a tu cargo o en proceso de solicitud');
        }

        const nuevaSolicitud = new ResponsableDe({
            fk_id_estudiante: estudianteExistente._id,
            fk_id_responsable: req.user.userId,
            estadoSolicitud: 'pendiente'
        });
        await nuevaSolicitud.save();

        res.send('Solicitud enviada al preceptor para aprobación.');
    } catch (error) {
        console.error('Error al enviar solicitud:', error);
        res.status(500).send('Error al enviar la solicitud');
    }
});

app.get('/solicitudes-preceptor/:cursoId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const solicitudesPendientes = await ResponsableDe.find({ estadoSolicitud: 'pendiente' })
            .populate({
                path: 'fk_id_estudiante',
                match: { cursoPerteneciente: req.params.cursoId },
                populate: { path: 'cursoPerteneciente' } // Popula la referencia al curso
            })
            .populate('fk_id_responsable');

        const filteredSolicitudes = solicitudesPendientes.filter(solicitud => solicitud.fk_id_estudiante !== null);

        res.render('solicitudesPreceptor', { solicitudes: filteredSolicitudes });
    } catch (error) {
        console.error('Error al obtener solicitudes:', error);
        res.status(500).send('Error al cargar las solicitudes pendientes.');
    }
});

app.get('/comunicados-curso/:cursoId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'responsable') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const comunicadosCurso = await Comunicado.find({ curso: req.params.cursoId })
            .populate('fk_id_preceptor')
            .populate('fk_id_directivo');

        const comunicadosGenerales = await Comunicado.find({ general: true })
            .populate('fk_id_preceptor')
            .populate('fk_id_directivo');

        const curso = await Curso.findById(req.params.cursoId);

        res.render('comunicadosCurso', { comunicadosCurso, comunicadosGenerales, curso });
    } catch (error) {
        console.error('Error al obtener comunicados del curso:', error);
        res.status(500).send('Error al obtener los comunicados.');
    }
});

app.post('/aceptar-solicitud/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const solicitud = await ResponsableDe.findById(req.params.id).populate('fk_id_estudiante');
        await ResponsableDe.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect(`/solicitudes-preceptor/${solicitud.fk_id_estudiante.cursoPerteneciente}`);
    } catch (error) {
        console.error('Error al aceptar solicitud:', error);
        res.status(500).send('Error al aceptar la solicitud.');
    }
});

app.post('/rechazar-solicitud/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const solicitud = await ResponsableDe.findById(req.params.id).populate('fk_id_estudiante');
        await ResponsableDe.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'rechazado' });
        res.redirect(`/solicitudes-preceptor/${solicitud.fk_id_estudiante.cursoPerteneciente}`);
    } catch (error) {
        console.error('Error al rechazar solicitud:', error);
        res.status(500).send('Error al rechazar la solicitud.');
    }
});

app.get('/responsables-rechazados/:cursoId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const responsablesRechazados = await ResponsableDe.find({ estadoSolicitud: 'rechazado' })
            .populate({
                path: 'fk_id_estudiante',
                match: { cursoPerteneciente: req.params.cursoId }
            })
            .populate('fk_id_responsable');

        res.render('responsablesRechazados', { responsablesRechazados });
    } catch (error) {
        console.error('Error al cargar responsables rechazados:', error);
        res.status(500).send('Error al cargar responsables rechazados.');
    }
});

app.post('/aceptar-rechazado/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    const cursoId = req.query.cursoId;

    try {
        await ResponsableDe.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect(`/responsables-rechazados/${cursoId}`);
    } catch (error) {
        console.error('Error al aceptar responsable rechazado:', error);
        res.status(500).send('Error al aceptar responsable rechazado.');
    }
});

app.get('/responsables-aceptados/:cursoId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const responsablesAceptados = await ResponsableDe.find({ estadoSolicitud: 'aceptado' })
            .populate({
                path: 'fk_id_estudiante',
                match: { cursoPerteneciente: req.params.cursoId }
            })
            .populate('fk_id_responsable');

        res.render('responsablesAceptados', { responsablesAceptados });
    } catch (error) {
        console.error('Error al cargar responsables aceptados:', error);
        res.status(500).send('Error al cargar responsables aceptados.');
    }
});

app.post('/dar-baja-responsable/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    const cursoId = req.query.cursoId;

    try {
        await ResponsableDe.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'dadobaja' });
        res.redirect(`/responsables-aceptados/${cursoId}`);
    } catch (error) {
        console.error('Error al dar de baja al responsable:', error);
        res.status(500).send('Error al dar de baja al responsable.');
    }
});

app.get('/responsables-baja/:cursoId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const responsablesBaja = await ResponsableDe.find({ estadoSolicitud: 'dadobaja' })
            .populate({
                path: 'fk_id_estudiante',
                match: { cursoPerteneciente: req.params.cursoId }
            })
            .populate('fk_id_responsable');

        res.render('responsablesBaja', { responsablesBaja });
    } catch (error) {
        console.error('Error al cargar responsables dados de baja:', error);
        res.status(500).send('Error al cargar responsables dados de baja.');
    }
});

app.post('/aceptar-baja/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'preceptor') {
        return res.status(403).send('Acceso denegado');
    }

    const cursoId = req.query.cursoId;  // Asegúrate de que el cursoId esté disponible en la query

    try {
        await ResponsableDe.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect(`/responsables-baja/${cursoId}`);
    } catch (error) {
        console.error('Error al aceptar responsable dado de baja:', error);
        res.status(500).send('Error al aceptar responsable dado de baja.');
    }
});

app.get('/admin-dashboard', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    res.render('adminDashboard', { admin: req.user });
});

app.get('/gestionar-usuarios', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const usuarios = await User.find();  // Obtiene todos los usuarios
        res.render('gestionarUsuarios', { usuarios });
    } catch (error) {
        console.error('Error al obtener los usuarios:', error);
        res.status(500).send('Error al cargar los usuarios.');
    }
});

async function createAdmin() {
    const hashedPassword = await bcrypt.hash('This_is_Roberto_Arlt', 10);
    const adminUser = new User({
        dni: '00000',
        email: 'admin@admin.com',
        password: hashedPassword,
        role: 'admin',
        isVerified: true
    });

    await adminUser.save();
    console.log('Usuario admin creado');
}

app.get('/solicitudes-directivos', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        const directivosPendientes = await Directivo.find({ estadoSolicitud: 'pendiente' });
        const directivosAceptados = await Directivo.find({ estadoSolicitud: 'aceptado' });
        const directivosRechazados = await Directivo.find({ estadoSolicitud: 'rechazado' });
        const directivosDadoBaja = await Directivo.find({ estadoSolicitud: 'dadobaja' });

        res.render('solicitudesDirectivos', {
            directivosPendientes,
            directivosAceptados,
            directivosRechazados,
            directivosDadoBaja
        });
    } catch (error) {
        console.error('Error al obtener solicitudes:', error);
        res.status(500).send('Error al obtener solicitudes.');
    }
});

app.post('/aceptar-directivo/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        await Directivo.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect('/solicitudes-directivos');
    } catch (error) {
        console.error('Error al aceptar directivo:', error);
        res.status(500).send('Error al aceptar directivo.');
    }
});

app.post('/rechazar-directivo/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        await Directivo.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'rechazado' });
        res.redirect('/solicitudes-directivos');
    } catch (error) {
        console.error('Error al rechazar directivo:', error);
        res.status(500).send('Error al rechazar directivo.');
    }
});

app.post('/dar-baja-directivo/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        await Directivo.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'dadobaja' });
        res.redirect('/solicitudes-directivos');
    } catch (error) {
        console.error('Error al dar de baja al directivo:', error);
        res.status(500).send('Error al dar de baja al directivo.');
    }
});

app.post('/aceptar-rechazado-directivo/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        await Directivo.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect('/solicitudes-directivos');
    } catch (error) {
        console.error('Error al aceptar directivo rechazado:', error);
        res.status(500).send('Error al aceptar directivo rechazado.');
    }
});

app.post('/aceptar-baja-directivo/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado');
    }

    try {
        await Directivo.findByIdAndUpdate(req.params.id, { estadoSolicitud: 'aceptado' });
        res.redirect('/solicitudes-directivos');
    } catch (error) {
        console.error('Error al aceptar directivo dado de baja:', error);
        res.status(500).send('Error al aceptar directivo dado de baja.');
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

app.get('/comunicados-preceptor', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'preceptor') {
            return res.status(403).send('Acceso denegado');
        }

        const cursosAsignados = await Curso_Preceptor.find({ fk_id_preceptor: req.user.userId }).populate('fk_id_curso').exec();

        const filtroCurso = req.query.cursoId ? { curso: req.query.cursoId } : {};
        const comunicados = await Comunicado.find({
            fk_id_preceptor: req.user.userId, 
            ...filtroCurso
        }).populate('curso').exec();

        res.render('comunicadosPreceptor', { comunicados, cursos: cursosAsignados.map(cp => cp.fk_id_curso) });
    } catch (error) {
        console.error('Error al obtener comunicados del preceptor:', error);
        res.status(500).send('Error al obtener los comunicados.');
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

app.get('/perfil', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; 
        console.log('Consultando el usuario con el ID:', userId);

        let userRoleData;

        switch (req.user.role) {
            case 'estudiante':
                userRoleData = await Estudiante.findById(userId).populate('cursoPerteneciente').exec();
                if (!userRoleData) {
                    return res.status(404).send('Estudiante no encontrado');
                }
                console.log('Datos del estudiante:', userRoleData);
                res.render('perfilEstudiante', { user: req.user, estudiante: userRoleData });
                break;
            
            case 'preceptor':
                userRoleData = await Preceptor.findById(userId).exec();
                if (!userRoleData) {
                    return res.status(404).send('Preceptor no encontrado');
                }
                console.log('Datos del preceptor:', userRoleData);
                res.render('perfilPreceptor', { user: req.user, preceptor: userRoleData });
                break;

            case 'responsable':
                userRoleData = await Responsable.findById(userId).exec();
                if (!userRoleData) {
                    return res.status(404).send('Responsable no encontrado');
                }
                console.log('Datos del responsable:', userRoleData);
                res.render('perfilResponsable', { user: req.user, responsable: userRoleData });
                break;

            case 'directivo':
                userRoleData = await Directivo.findById(userId).exec();
                if (!userRoleData) {
                    return res.status(404).send('Directivo no encontrado');
                }
                console.log('Datos del directivo:', userRoleData);
                res.render('perfilDirectivo', { user: req.user, directivo: userRoleData });
                break;

            default:
                return res.status(400).send('Rol no reconocido');
        }

    } catch (error) {
        console.error('Error al cargar el perfil:', error);
        res.status(500).send('Error al cargar el perfil');
    }
});

app.post('/upload-profile-picture', authenticateToken, upload.single('fotoPerfil'), async (req, res) => {
    try {
        const userId = req.user.userId;
        const filePath = `/uploads/${req.file.filename}`; // Ruta donde se almacenará la imagen

        switch (req.user.role) {
            case 'estudiante':
                await Estudiante.findByIdAndUpdate(userId, { fotoPerfil: filePath });
                break;
            case 'preceptor':
                await Preceptor.findByIdAndUpdate(userId, { fotoPerfil: filePath });
                break;
            case 'responsable':
                await Responsable.findByIdAndUpdate(userId, { fotoPerfil: filePath });
                break;
            case 'directivo':
                await Directivo.findByIdAndUpdate(userId, { fotoPerfil: filePath });
                break;
            default:
                return res.status(400).send('Rol no reconocido');
        }

        res.redirect('/perfil');
    } catch (error) {
        console.error('Error al subir la foto de perfil:', error);
        res.status(500).send('Error al subir la foto de perfil');
    }
});

app.listen(3000, () => {
    console.log('Servidor escuchando en http://localhost:3000');
});