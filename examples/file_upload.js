/*
**
**  Example of Node.js file upload server to write data to CDN
**
*/

const http = require('http');
const fs = require('fs');
const mmh3 = require('murmurhash3');
const formidable = require('formidable');

var config = {
	host = '0.0.0.0',
	port = 8080,
	root = "/opt/cdn",
	depth = 4,
};

var server = http.createServer(function(request, response) {
    const form = formidable({ multiples: true });

    form.parse(req);

    form.on('file', function (name, file){
        console.log('Uploaded ' + file.name);

		// TODO: WRITE YOUR AUTHORISATION CODE HERE

		// TODO: WRITE FILE METADATA TO METADATA STORAGE (DATABASE) HERE

		// Read the file
		//FIXME: This is simple, but inefficient, sice we read the back the file after it has been written
		var data = fs.readFileSync(file.path);

		// Calculate hash
		// TODO: It is a good idea to use additional input info: user ID, timestamp, server ID.
		// You want to guarantee that no two uploads will have the same ID even if the same user uplaods them to the same server in the same time.
		// NB: Avoid using any random data, as entropy may be scarce and this will block or slow your upload processing.
		var hash = murmur128HexSync(data);

		// Determine file path from hash
		var path = config.root + '/';
		for (var i=0; i < config.depth; i++)
			path += hash.subsrting(i, i+1) + '/';
		path += hash;

		// Move file
		fs.renameSync(file.path, path);

		res.writeHead(200, {});
		res.end();
    });
});

server.listen(config.port, config.host);
console.log("Started web server on port " + config.port + " with FS Root " + config.root);


