var mysql      = require('mysql');
var conn = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : '071464',
  database : 'o2'
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