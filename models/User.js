const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    dni: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['preceptor', 'profesor', 'estudiante', 'responsable', 'directivo'] },
    fk_id_preceptor: { type: mongoose.Schema.Types.ObjectId, ref: 'Preceptor' },
    fk_id_profesor: { type: mongoose.Schema.Types.ObjectId, ref: 'Profesor' },
    fk_id_estudiante: { type: mongoose.Schema.Types.ObjectId, ref: 'Estudiante' },
    fk_id_responsable: { type: mongoose.Schema.Types.ObjectId, ref: 'Responsable' },
    fk_id_directivo: { type: mongoose.Schema.Types.ObjectId, ref: 'Directivo' },
    isVerified: { type: Boolean, default: false },  // Campo para verificar si el usuario ha verificado su cuenta
    verificationToken: { type: String, default: null },  // Campo para almacenar el token de verificación
    verificationTokenExpires: { type: Date, default: null },  // Campo para manejar la expiración del token
});

module.exports = mongoose.model('User', userSchema);
