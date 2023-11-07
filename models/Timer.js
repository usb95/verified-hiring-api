
const mongoose = require('mongoose');

const timerSchema = new mongoose.Schema({
    user: String,
    time: Number,
    action: String,
});

const Timer = mongoose.model('Timer', timerSchema);

module.exports = Timer;
