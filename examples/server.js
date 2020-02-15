/*
**
**  Example of Interprocess communication in Node.js through a UNIX domain socket
**
*/

var net = require('net'),
    fs = require('fs'),
    connections = {},
    server, client
    ;

// prevent duplicate exit messages
var SHUTDOWN = false;

// Our socket
const SOCKETFILE = '/tmp/unix.sock';

console.info('Loading interprocess communications test');
console.info('  Socket: %s \n  Process: %s',SOCKETFILE,process.pid);

function createServer(socket){
    console.log('Creating server.');
    var server = net.createServer({allowHalfOpen: true}, function(stream) {
        console.log('Connection acknowledged.');

        // Store all connections so we can terminate them if the server closes.
        // An object is better than an array for these.
        var self = Date.now();
        connections[self] = (stream);
        stream.on('end', function() {
            console.log('Client disconnected.');
	        stream.write('__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop');
			stream.end();
            delete connections[self];
        });

        // Messages are buffers. use toString
        stream.on('data', function(msg) {
            msg = msg.toString();
            console.log('Client:', msg);

	        //stream.write('__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop__boop');
			//stream.end();
        });
    })
    .listen(socket)
    .on('connection', function(socket){
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

