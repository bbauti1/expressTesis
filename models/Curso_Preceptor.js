const mongoose = require('mongoose');

const cursoPreceptorSchema = new mongoose.Schema({
    fk_id_preceptor: { type: mongoose.Schema.Types.ObjectId, ref: 'Preceptor', required: true },
    fk_id_curso: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true },
    dadoAlta: { type: Boolean, default: false },
    dadoBaja: { type: Boolean, default: false },
    fechaDadoDeAlta: { type: Date },
    fechaDadoDeBaja: { type: Date }
});

module.exports = mongoose.model('Curso_Preceptor', cursoPreceptorSchema);
