const {Schema, model} = require('mongoose')

const userSchema = new Schema({
    id: {
        type: String,
    },
    username: {
        type: String,
    },
    password: {
        type: String,
    },
})

module.exports = model('Users', userSchema)