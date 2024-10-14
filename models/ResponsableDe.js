const mongoose = require('mongoose');

const ResponsableDeSchema = new mongoose.Schema({
    fk_id_estudiante: { type: mongoose.Schema.Types.ObjectId, ref: 'Estudiante', required: true },
    fk_id_responsable: { type: mongoose.Schema.Types.ObjectId, ref: 'Responsable', required: true },
    estadoSolicitud: { type: String, enum: ['pendiente', 'aceptado', 'rechazado', 'dadobaja'], default: 'pendiente' }  // Agregado el estado de la solicitud
});

module.exports = mongoose.model('ResponsableDe', ResponsableDeSchema);
