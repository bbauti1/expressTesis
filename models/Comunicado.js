const mongoose = require('mongoose');

const ComunicadoSchema = new mongoose.Schema({
    titulo: { type: String, required: true },
    info: { type: String, required: true },
    curso: { type: String, required: true, enum: ['7° 1°', '6° 1°', '5° 1°'] },
    fk_id_preceptor: { type: mongoose.Schema.Types.ObjectId, ref: 'Preceptor', required: true }
}, { timestamps: true });

module.exports = mongoose.model('Comunicado', ComunicadoSchema);
