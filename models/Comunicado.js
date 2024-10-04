const mongoose = require('mongoose');

const comunicadoSchema = new mongoose.Schema({
    titulo: { type: String, required: true },
    info: { type: String, required: true },
    curso: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', default: null },  // Puede ser null si es general
    general: { type: Boolean, default: false },  // Indica si es un comunicado general para todos
    fk_id_preceptor: { type: mongoose.Schema.Types.ObjectId, ref: 'Preceptor', default: null },
    fk_id_directivo: { type: mongoose.Schema.Types.ObjectId, ref: 'Directivo', default: null }
});

module.exports = mongoose.model('Comunicado', comunicadoSchema);
