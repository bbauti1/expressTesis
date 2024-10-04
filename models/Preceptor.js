const mongoose = require('mongoose');

const PreceptorSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    cursoACargo: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true }, // Cambiado a ObjectId
    email: { type: String, required: true, unique: true }, 
});

module.exports = mongoose.model('Preceptor', PreceptorSchema);
