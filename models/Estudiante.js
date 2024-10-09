const mongoose = require('mongoose');

const EstudianteSchema = new mongoose.Schema({
    nroCarnet: { type: String, required: true, unique: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    cursoPerteneciente: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true },
    email: { type: String, required: true, unique: true },
    estado: { type: String, enum: ['pendiente', 'aceptado', 'rechazado', 'dadobaja'], default: 'pendiente' } // Agregado estado
});

module.exports = mongoose.model('Estudiante', EstudianteSchema);
