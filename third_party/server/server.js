var http = require("http");
var https = require("https");
var express = require("express");
var bodyParser = require('body-parser');
var cors = require('cors');
var compression = require('compression');

var fs = require('fs');

var port = process.env.PORT || 7777;

var app = express();

app.use(compression());
app.use(cors());

app.use(function(req, res, next) {
  res.header("Cross-Origin-Embedder-Policy", "require-corp");
  res.header("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

app.get('/query', function(req, res){
    
    if (req.query.stat) {

	fs.stat(__dirname + req.query.stat, (error, stats) => {
	    
	    if (error) {
		/*console.log(error);*/

		res.send("errno=-2");
	    }
	    else {
		/*console.log("Stats object for: "+req.query.stat);
		console.log(stats);
		
		// Using methods of the Stats object
		console.log("Path is file:", stats.isFile());
		console.log("Path is directory:", stats.isDirectory());*/

		let mode = 00444;

		if (stats.isDirectory()) {

		    //console.log("It is a directory");

		    mode |= 00111;

		    try {

			statsObj2 = fs.statSync(__dirname +req.query.stat+"/exa");

			//console.log(statsObj2);

			//console.log("exa dir exists");

			mode |= 0100000;
			
		    }
		    catch {

			mode |= 0040000;
		    }
		}
		else {

		    mode |= 0100000;
		}

		res.send("errno=0\nmode="+mode+"\nsize="+stats.size);
	    }
	});
    }
    else if (req.query.getdents) {

	fs.readdir(__dirname + req.query.getdents, (err, files) => {
	    
	    if (err)
		res.send("errno=-1");
	    else {

		let str = "errno=0\n";
		
		files.forEach(file => {

		    let slash = "/";

		    if (req.query.getdents.slice(-1) == "/")
			slash = "";

		    statsObj = fs.statSync(__dirname + req.query.getdents+slash+file);

		    let mode = 00444;

		    if (statsObj.isDirectory()) {

			//console.log("It is a directory");

			mode |= 00111;

			try {

			    statsObj2 = fs.statSync(__dirname + req.query.getdents+slash+file+"/exa");
			    
			    //console.log(statsObj2);
			    
			    //console.log("exa dir exists");

			    mode |= 0100000;
			    
			}
			catch {

			    mode |= 0040000;
			}
		    }
		    else {

			mode |= 0100000;
		    }

		    str += file+";"+mode+";"+statsObj.size+"\n";
		})

		res.send(str);
	    }
	})
    }
    else {

	res.send("errno=-1");
    }
});

app.use(express.static(__dirname));

var server = http.createServer(app);

server.listen(port, '0.0.0.0');
