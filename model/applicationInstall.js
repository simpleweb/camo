var Schema          = require('mongoose').Schema

ObjectId = Schema.Types.ObjectId;

exports.applicationInstall = applicationInstall = new Schema({ 
    _id : ObjectId, 
    label : String, 
    application : { 
        $id : ObjectId 
    }}, 
    { collection : 'applicationInstall' });

