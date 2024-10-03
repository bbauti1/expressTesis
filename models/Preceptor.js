const mongoose = require('mongoose');

const PreceptorSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    cursoACargo: { type: String, required: true, enum: ['7° 1°', '6° 1°', '5° 1°'] },
    email: { type: String, required: true, unique: true }, // Añadir email
});

module.exports = mongoose.model('Preceptor', PreceptorSchema);
