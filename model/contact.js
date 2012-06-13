var Schema          = require('mongoose').Schema

/**
 * Represents a blog post comment
 * @name Comment
 * @version 0.1
 * @class Comment
 * @requires mongoose
 * @augments Schema
 */
exports.contact = contact = new Schema({
    name: { type: String },
    poco: {
        photos: [{
          primary:   { type: String },
          value:    { type: String }
        }]
    }
}, { collection : 'contact' });
