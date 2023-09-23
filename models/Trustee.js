const mongoose = require('mongoose');

const trusteeSchema = new mongoose.Schema({
    index: { type: Number, required: true, unique: true },
    sk: { type: Object, required: true }
});

module.exports = mongoose.model('Trustee', trusteeSchema);
