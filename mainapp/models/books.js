const {Schema, model} = require('mongoose')

const bookSchema = new Schema({
    id: {
        type: String,
    },
    title: {
        type: String,
        default: "",
    },
    description: {
        type: String,
        default: "",
    },
    authors: {
        type: String,
        default: "",
    },
    favorite: {
        type: String,
        default: "",
    },
    fileCover: {
        type: String,
        default: "",
    },
    fileName: {
        type: String,
        default: "",
    },
})

module.exports = model('Books', bookSchema)