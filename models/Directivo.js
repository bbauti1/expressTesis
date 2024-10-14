const mongoose = require('mongoose');

const directivoSchema = new mongoose.Schema({
    dni: { type: String, required: true, unique: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    estadoSolicitud: { type: String, enum: ['pendiente', 'aceptado', 'rechazado', 'dadobaja'], default: 'pendiente' },
    fotoPerfil: { type: String, default: '/images/defaultProfile.png' },
});

module.exports = mongoose.model('Directivo', directivoSchema);
