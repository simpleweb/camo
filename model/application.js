var Schema          = require('mongoose').Schema

ObjectId = Schema.Types.ObjectId;

exports.application = application = new Schema({ 
    _id : ObjectId, 
    appName : String
}, { collection : 'application' });

