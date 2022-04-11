const client = require('dgram').createSocket('udp4');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const [node, file, command, ...args] = process.argv;
const public_key = fs.readFileSync('public.pem');

var key;

const options = {
  port: 4000,
  host: '127.0.0.1',
};

switch (command) {
  case 'register':
    send_register_data(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
    break;
  case 'login':
    send_login_data(args[0], args[1]);
    break;
  case 'help':
    help();
    break;
  default:
    console.log(`${command} is not a recognized command. Find some helpful commands ${help()}`);
    break;
}
function send_register_data(email, username, password, address, invoice_type, year, month, amount) {
  if (!validate(email, username, password, address, invoice_type, year, month, amount)) {
    console.log('Wrong parameters given! Please type help to see how to send them');
    process.exit();
  }

  const message = Buffer.from(
    JSON.stringify({
      request: 'register',
      email,
      username,
      password,
      address,
      invoice_type,
      year,
      month,
      amount,
    })
  );
  return SendEncrypted(message, options.port, options.host);
}

function send_login_data(email, password) {
  if (!validate(email, password)) {
    console.log('Wrong parameters given! Please type help to see how to send them');
    process.exit();
  }

  const message = Buffer.from(
    JSON.stringify({
      request: 'login',
      email: args[0],
      password: args[1],
    })
  );
  return SendEncrypted(message, options.port, options.host);
}

function validate(...args) {
  for (let i = 0; i < args.length; i++) {
    if (!args[i]) {
      return false;
    }
  }
  return true;
}

client.on('message', (data) => {
  const message = JSON.parse(Decrypt(data));

  if (message.type == 'login_ok' || message.type == 'register_ok') {
    jwt.verify(message.info, public_key, (err, decoded) => {
      if (err) {
        console.log('JWT from the server is invalid');
      } else {
        console.log('JWT is valid, message received:\n', decoded);
      }
    });
  } else {
    console.log(`Message received: ${message.status_type} with message: ${message.status_message}`);
  }

  process.exit();
});

client.on('error', (err) => {
  console.log(err.message);
});

function help() {
  console.log('To login type: node client.js login email password');
  console.log(
    'To register type: node client.js register email username password address invoice_type year month amount'
  );
  console.log('To get help type: node client.js help');
}

function SendEncrypted(message, port, ip) {
  const [encrypted, iv, rsaEncryptedKey] = EncodeDesCBC(message);
  client.send(Buffer.from(iv + '.' + rsaEncryptedKey + '.' + encrypted, 'utf8'), port, ip);
}

function Decrypt(message) {
  const [iv, encrypted] = message.toString('utf8').split('.');
  const decrypted = crypto.createDecipheriv('des-cbc', Buffer.from(key), Buffer.from(iv, 'base64'));
  let d = decrypted.update(encrypted, 'base64', 'utf8');
  d += decrypted.final('utf8');
  return d;
}

function EncodeDesCBC(text_to_encode) {
  key = crypto.randomBytes(8);
  const iv = crypto.randomBytes(8);
  const cipher = crypto.createCipheriv('des-cbc', key, iv);
  let c = cipher.update(text_to_encode, 'utf8', 'base64');
  c += cipher.final('base64');
  const rsaEncryptedKey = crypto.publicEncrypt(public_key, key).toString('base64');
  return [c, iv.toString('base64'), rsaEncryptedKey];
}
