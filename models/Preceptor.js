const mongoose = require('mongoose');

const PreceptorSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true }, 
});

module.exports = mongoose.model('Preceptor', PreceptorSchema);
