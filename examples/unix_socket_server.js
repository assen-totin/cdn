/*
**
**  Example of Node.js Unix domain socket server to use with CDN as authorisation body
**
*/

var net = require('net'),
    fs = require('fs'),
    connections = {},
	input = {},
    server, client
    ;

// prevent duplicate exit messages
var SHUTDOWN = false;

// Our socket
const SOCKETFILE = '/tmp/unix.sock';

console.info('  Socket: %s \n  Process: %s',SOCKETFILE,process.pid);

function createServer(socket){
    console.log('Creating server.');
    var server = net.createServer({allowHalfOpen: true}, function(stream) {
        // Store all connections so we can terminate them if the server closes.
        // An object is better than an array for these.
        var self = Date.now();
        connections[self] = (stream);
        input[self] = '';
        stream.on('end', function() {
			console.log('Client sent: ' + input[self]);
            console.log('Client disconnected.');

			//TODO: process the authorisation request here and prepare response from file metadata
			var response = {};

	        stream.write(JSON.stringify(response));
			stream.end();
            delete connections[self];
            delete input[self];
        });

        // Messages are buffers, so convert them to strings
        stream.on('data', function(msg) {
            input[self] += msg.toString();
            console.log('Client:', msg);
        });
    })
    .listen(socket)
    .on('connection', function(socket) {
        console.log('Client connected.');
    })
    ;
    return server;
}

// check for failed cleanup
console.log('Checking for leftover socket.');
fs.stat(SOCKETFILE, function (err, stats) {
    if (err) {
        // start server
        console.log('No leftover socket found.');
        server = createServer(SOCKETFILE); return;
    }
    // remove file then start server
    console.log('Removing leftover socket.')
    fs.unlink(SOCKETFILE, function(err){
        if(err){
            // This should never happen.
            console.error(err); process.exit(0);
        }
        server = createServer(SOCKETFILE); return;
    });  
});

// close all connections when the user does CTRL-C
function cleanup(){
    if(!SHUTDOWN){ SHUTDOWN = true;
        console.log('\n',"Terminating.",'\n');
        if(Object.keys(connections).length){
            let clients = Object.keys(connections);
            while(clients.length){
                let client = clients.pop();
                connections[client].write('__disconnect');
                connections[client].end(); 
            }
        }
        server.close();
        process.exit(0);
    }
}
process.on('SIGINT', cleanup);

