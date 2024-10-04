const mongoose = require('mongoose');

const CursoSchema = new mongoose.Schema({
    anio: { type: Number, required: true },
    division: { type: String, required: true },
});

module.exports = mongoose.model('Curso', CursoSchema);
