const mongoose = require('mongoose');
const uuidv4 = require('uuid').v4;

const electionSchema = new mongoose.Schema({
    uuid: { type: String, default: uuidv4 },
    title: { type: String, required: true, unique: true },
    description: String,
    question: { type: String, required: true },
    email: { type: String, required: true },
    startTime: { type: Date, required: true },
    endTime: { type: Date, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }  // 可以用来关联创建选举的用户
});

module.exports = mongoose.model('Election', electionSchema);
