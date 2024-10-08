const mongoose = require('mongoose');

const PreceptorSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    estado: { type: String, enum: ['pendiente', 'aceptado', 'rechazado', 'dadobaja'], default: 'pendiente' }
});

module.exports = mongoose.model('Preceptor', PreceptorSchema);
