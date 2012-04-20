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
        urls : [{
          name:   { type: String },
          value:    { type: String }
        }],
        accounts: [{
          domain:   { type: String },
          username:    { type: String },
          userid:    { type: String },
          sgnode: {type: String }
        }]
    }
}, { collection : 'contact' });


contact.pre('save', function (next) {
  this.poco.urls=uniqueUrls(this.poco.urls);
  this.poco.accounts=uniqueAccounts(this.poco.accounts);
  next();
});

var uniqueUrls = function(origArr) {  
    var newArr = [],  
        origLen = origArr.length,  
        found,  
        x, y;  
  
    for ( x = 0; x < origLen; x++ ) {  
        found = undefined;  
        for ( y = 0; y < newArr.length; y++ ) {  
            if ( origArr[x].value === newArr[y].value ) {  
              found = true;
              break;
            }  
        }  
        if ( !found) newArr.push( origArr[x] );  
    }  
   return newArr;  
};

var uniqueAccounts = function(origArr) {  
    var newArr = [],  
        origLen = origArr.length,  
        found,  
        x, y;  
  
    for ( x = 0; x < origLen; x++ ) {  
        found = undefined;  
        for ( y = 0; y < newArr.length; y++ ) {  
            if ( origArr[x].sgnode === newArr[y].sgnode ) {  
              found = true;
              break;
            }  
        }  
        if ( !found) newArr.push( origArr[x] );  
    }  
   return newArr;  
};
