const mongoose = require('mongoose');

const CursoSchema = new mongoose.Schema({
    anio: { type: Number, required: true },
    division: { type: String, required: true },
    fk_id_preceptor: { type: mongoose.Schema.Types.ObjectId, ref: 'Preceptor', required: true }
});

module.exports = mongoose.model('Curso', CursoSchema);
