const mongoose = require('mongoose');

const ProfesorSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Añadir email
});

module.exports = mongoose.model('Profesor', ProfesorSchema);