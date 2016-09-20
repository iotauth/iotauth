const dgram = require('dgram');
const message = Buffer.from('Some bytes');
const socket = dgram.createSocket('udp4');

socket.on('listening', () => {
  var address = socket.address();
  console.log(`server listening ${address.address}:${address.port}`);
});

socket.on('message', (msg, rinfo) => {
	console.log('some message received?')
  	console.log('Received %d bytes from %s:%d\n',
	msg.length, rinfo.address, rinfo.port);
});

socket.bind();


socket.send(message, 0, message.length, 21902, 'localhost', (err) => {
	//socket.close();
});

function commandInterpreter() {
    var chunk = process.stdin.read();
    if (chunk != null) {
    	console.log(chunk);
    }
}

process.stdin.on('readable', commandInterpreter);
