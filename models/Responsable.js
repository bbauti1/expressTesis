const mongoose = require('mongoose');

const ResponsableSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    dni: { type: String, required: true, unique: true },
    telefono: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    fotoPerfil: { type: String, default: '/images/defaultProfile.png' },
});

module.exports = mongoose.model('Responsable', ResponsableSchema);
