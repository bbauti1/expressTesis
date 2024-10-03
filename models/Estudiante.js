const mongoose = require('mongoose');

const EstudianteSchema = new mongoose.Schema({
    nroCarnet: { type: String, required: true, unique: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    cursoPerteneciente: { type: String, required: true, enum: ['7° 1°', '6° 1°', '5° 1°'] },
    email: { type: String, required: true, unique: true }, // Añadir email
});

module.exports = mongoose.model('Estudiante', EstudianteSchema);
