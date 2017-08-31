var mysql      = require('mysql');
var conn = mysql.createConnection({
  host     : 'us-cdbr-iron-east-05.cleardb.net',
  user     : 'b2212031659833',
  password : 'aeb44d8b',
  database : 'heroku_c7374f367bb0cba'
});

conn.connect();

var sql = 'SELECT * FROM topic';
conn.query(sql, function(err, rows, fields){
  if(err){
    console.log(err);
  } else {
    // console.log('rows', rows);
    // console.log('fields', fields);
    for (var i=0; i<rows.length;i++){
      console.log(rows[i].author);
    }
  }
});
conn.end();
