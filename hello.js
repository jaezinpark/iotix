var express = require('express');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);
var bodyParser = require('body-parser');
var multer = require('multer');
var upload = multer();

var bkfd2Password = require("pbkdf2-password");
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var hasher = bkfd2Password();
var mysql      = require('mysql');
/*
var conn = mysql.createConnection({
  host     : 'us-cdbr-iron-east-05.cleardb.net',
  user     : 'b2212031659833',
  password : 'aeb44d8b',
  database : 'heroku_c7374f367bb0cba'
});
*/
var pool = mysql.createPool({
  connectionLimit: 10,
  host     : 'us-cdbr-iron-east-05.cleardb.net',
  user     : 'b2212031659833',
  password : 'aeb44d8b',
  database : 'heroku_c7374f367bb0cba'
});
/*
conn.connect(function(err){
  console.log(err);
});
conn.on('error', function (err){
  console.log('conn.on: ' + err.code);
});
*/
var app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: '1234DSFs@adf1234!@#$asd',
  resave: false,
  saveUninitialized: true,
  store:new MySQLStore({
    host     : 'us-cdbr-iron-east-05.cleardb.net',
    port     : 3306,
    user     : 'b2212031659833',
    password : 'aeb44d8b',
    database : 'heroku_c7374f367bb0cba'
  })
}));
app.use(passport.initialize());
app.use(passport.session());

app.get('/count', function(req, res){
  if(req.session.count) {
    req.session.count++;
  } else {
    req.session.count = 1;
  }
  res.send('count : '+req.session.count);
});

// logout api :
app.get('/auth/logout', function(req, res){
  req.logout();
  var resData = {
    code: '1000',
    message: '로그아웃 되었습니다'
  };
  return res.json(resData);
});

//passport
//session 에 저장됨
passport.serializeUser(function(user, done) {
  console.log('serializeUser', user);
  done(null, user.authid);
});
// 로그인 이후 접속시
passport.deserializeUser(function(id, done) {
  console.log('deserializeUser', id);
  var sql = 'SELECT * FROM users WHERE authid=?';
  pool.getConnection(function(error, conn) {
      if (error) { throw error; }

      conn.query(sql, [id], function(err, results){
        if (err) { throw err; }
        if(err){
          console.log(err);
          done('There is no user.');
        } else {
          done(null, results[0]);
        }
        conn.release();
      });

  });
});
passport.use(new LocalStrategy(
  function(username, password, done){
    var uname = username;
    var pwd = password;
    var sql = 'SELECT * FROM users WHERE authid=?';
    var msgNouser = '가입된 사용자가 아닙니다.';
    var msgNopass = '패스워드가 잘못되었습니다.';

    pool.getConnection(function(error, conn) {
        if (error) { throw error; }

        conn.query(sql, ['local:'+uname], function(err, results){
          if (err) { throw err; }
          if(err){
            console.log(msgNouser);
            conn.release();
            return done(null, false, { code: 9011, message: '가입된 사용자가 아닙니다.' });
          }
          if(results.length === 0){
            console.log(msgNouser);
            conn.release();
            return done(null, false, { code: 9011, message: '가입된 사용자가 아닙니다.' });
          } else {
            var user = results[0];
            conn.release();
            return hasher({password:pwd, salt:user.salt}, function(err, pass, salt, hash){
              if(hash === user.password){
                console.log('use LocalStrategy', user);
                return done(null, user);
              } else {
                console.log(msgNopass);
                return done(null, false, { code: 9012, message: '패스워드가 잘못되었습니다.' });
              }
            });
          }
        });
    });
  }
));

// 로그인 api : 성공, 실패 처리
app.post(
  '/auth/login',
  function(req, res, next) {

  //  패스포트 모듈로 인증 시도
  passport.authenticate('local', function (err, user, info) {
      var error = err || info;
      if (error) return res.status(401).json(error);
      if (!user) return res.status(404).json({message: 'Something went wrong, please try again.'});

      // 인증된 유저 정보로 응답
      //res.json(req.user);
      var resData = {
        code: '1000',
        message: '로그인 되었습니다',
        authid: user.authid,
        nickname: user.nickname
      };
      return res.json(resData);
    })(req, res, next);
  }
);

// 회원가입 api
app.post('/auth/register', function(req, res){
  console.log(req.body);
  // private username: string;
  // private password: string;
  // private nickname: string;

  hasher({password:req.body.password}, function(err, pass, salt, hash){
    var user = {
      authid:'local:'+req.body.username,
      username:req.body.username,
      password:hash,
      salt:salt,
      nickname:req.body.nickname
    };
    var sql = 'INSERT INTO users SET ?';

    pool.getConnection(function(error, conn) {
        if (error) { throw error; }

        conn.query(sql, user, function(err, results){
          //if (err) { throw err; }
          if(err){
            console.log(err.errno);
            if(err.errno === 1582 || err.errno === 1062){
                var resData = {
                  code: '9001',
                  message: '사용중인 ID입니다'
                };
                conn.release();
                return res.json(resData);
            } else {
                conn.release();
                res.status(500);
            }

          } else {
            req.login(user, function(err){
              if (err) { throw err; }

              req.session.save(function(){
                var resData = {
                  code: '1000',
                  message: '가입되었습니다',
                  authid: user.authid,
                  nickname: user.nickname
                };
                conn.release();
                return res.json(resData);
              });
            });
          }
        });

    });

  });
});

// 3.주문리스트  : GET /orders/:authid
app.get('/orders/:authid',
  function(req, res){
  console.log(req.params.authid);
  var order = {
    sellerid: req.params.authid
  }
  var sql = 'SELECT * FROM orders WHERE ? ORDER BY orderdate DESC ';

  pool.getConnection(function(error, conn) {
      if (error) { throw error; }

      conn.query(sql, order, function(err, results){
        if (err) { throw err; }
        if(err){
          console.log(err.errno);
          conn.release();
        } else {
          var resData = {
            code: '1000',
            message: results
          };
          console.log(results);
          conn.release();
          return res.json(resData);
        }
      });

  });
});

// 4.주문등록   : POST /orders/:authid
app.post(
  '/orders/:authid',
  function(req, res){
  console.log(req.body);

  //주문일시, 이름, 연락처, 주소, 상품, 금액, 택배비, 기타
  var order = {
    sellerid: req.params.authid,
    orderdate: req.body.orderDate,
    ordername: req.body.orderName,
    orderphone: req.body.orderPhone,
    recpaddress: req.body.recpAddress,
    products: req.body.products,
    orderamount: req.body.orderAmount,
    deliverycharge: req.body.deliveryCharge,
    ordermemo: req.body.orderMemo,
    paymentyn: req.body.paymentyn,
    sendyn: req.body.sendyn
  }
  var sql = 'INSERT INTO orders SET ?';
  pool.getConnection(function(error, conn) {
      if (error) { throw error; }

      conn.query(sql, order, function(err, results){
        if (err) { throw err; }
        if(err){
          console.log(err.errno);
          conn.release();
        } else {
          var resData = {
            code: '1000',
            message: '주문이 등록되었습니다'
          };
          conn.release();
          return res.json(resData);
        }
      });

  });
});

// 5.주문삭제   : DELETE /orders/:authid/:oid
app.delete('/orders/:authid/:oid',
  function(req, res){
  console.log(req.params.oid);

  var sql = 'DELETE FROM orders WHERE ordernum=' + req.params.oid;
  pool.getConnection(function(error, conn) {
      if (error) { throw error; }

      conn.query(sql, function(err, results){
        if (err) { throw err; }
        if(err){
          console.log(err.errno);
          conn.release();
        } else {
          var resData = {
            code: '1000',
            message: '주문이 삭제되었습니다'
          };
          conn.release();
          return res.json(resData);
        }
      });
  });
});

// 6.주문수정   : PUT /orders/:authid/:oid
app.put('/orders/:authid/:oid',
  function(req, res){
  console.log(req.body);

  //주문일시, 이름, 연락처, 주소, 상품, 금액, 택배비, 기타
  var order = {
    sellerid: req.params.authid,
    orderdate: req.body.orderDate,
    ordername: req.body.orderName,
    orderphone: req.body.orderPhone,
    recpaddress: req.body.recpAddress,
    products: req.body.products,
    orderamount: req.body.orderAmount,
    deliverycharge: req.body.deliveryCharge,
    ordermemo: req.body.orderMemo,
    paymentyn: req.body.paymentyn,
    sendyn: req.body.sendyn
  }
  var sql = 'UPDATE orders SET ? WHERE ordernum=' + req.params.oid;
  pool.getConnection(function(error, conn) {
      if (error) { throw error; }

      conn.query(sql, order, function(err, results){
        if (err) { throw err; }
        if(err){
          console.log(err.errno);
          conn.release();
        } else {
          var resData = {
            code: '1000',
            message: '주문이 수정되었습니다'
          };
          conn.release();
          return res.json(resData);
        }
      });

  });
});

//app.set('port', (process.env.PORT || 5000));
var port = process.env.PORT || 5000;
app.listen(port, function(){
  console.log('Connected ' + port + ' port!!!');
});
