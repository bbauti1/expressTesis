const mongoose = require('mongoose');

const EstudianteSchema = new mongoose.Schema({
    nroCarnet: { type: String, required: true, unique: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    cursoPerteneciente: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true }, // Cambiado a ObjectId
    email: { type: String, required: true, unique: true }, 
});

module.exports = mongoose.model('Estudiante', EstudianteSchema);
