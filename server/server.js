const server = require('dgram').createSocket('udp4');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('db.json');
const db = low(adapter);

const private_key = fs.readFileSync('private.key');

server.bind(4000);

db.defaults({
  users: [],
}).write();
server.on('message', async (data, rinfo) => {
  const [message, key, iv] = Decrypt(data);
  const request_info = JSON.parse(message);

  switch (request_info.request) {
    case 'login':
      await Login(request_info, key, iv, rinfo);
      break;
    case 'register':
      await Register(request_info, key, iv, rinfo);
      break;
    default:
      SendEncrypted(
        HandleError('command_error', 'Wrong command provided'),
        rinfo.port,
        rinfo.address,
        key,
        iv
      );
      break;
  }
});

server.on('error', (err) => {
  console.log(`server error:\n${err.stack}`);
  server.close();
});

async function Login(data, key, iv, rinfo) {
  const user = db.get('users').find({ email: data.email }).value();

  if (typeof user === 'undefined')
    return SendEncrypted(
      HandleError('login_error', 'Wrong username or password'),
      rinfo.port,
      rinfo.address,
      key,
      iv
    );

  const match = await ComparePassword(data.password, user.password);

  if (!match) {
    return SendEncrypted(
      HandleError('login_error', 'Wrong username or password'),
      rinfo.port,
      rinfo.address,
      key,
      iv
    );
  } else {
    const { password, ...rest } = user;
    return SendEncrypted(
      { type: 'login_ok', info: await GenerateJWT(rest) },
      rinfo.port,
      rinfo.address,
      key,
      iv
    );
  }
}

async function Register(data, key, iv, rinfo) {
  const user = db.get('users').find({ email: data.email }).value();

  if (typeof user !== 'undefined')
    return SendEncrypted(
      HandleError('register_error', 'User already exists'),
      rinfo.port,
      rinfo.address,
      key,
      iv
    );

  const user_data = db
    .get('users')
    .push({
      id: uuidv4(),
      email: data.email,
      username: data.username,
      password: await HashPassword(data.password),
      address: data.address,
      invoice_type: data.invoice_type,
      year: data.year,
      month: data.month,
      amount: data.amount,
    })
    .write();

  const { password, ...rest } = user_data[user_data.length - 1];

  return SendEncrypted(
    { type: 'register_ok', info: await GenerateJWT(rest) },
    rinfo.port,
    rinfo.address,
    key,
    iv
  );
}

function HandleError(status_type, status_message) {
  return { status_type, status_message };
}

const ComparePassword = async (password, hashed_password) => {
  return new Promise((resolve, reject) => {
    try {
      resolve(bcrypt.compareSync(password, hashed_password));
    } catch (e) {
      reject(e);
    }
  });
};

async function HashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function GenerateJWT(user) {
  const payload = {
    user: user,
  };

  return jwt.sign(payload, private_key, {
    expiresIn: '1h',
    algorithm: 'RS256',
  });
}

// Create a function that sends encrypted data to the client using encoded DES-CBC function below
function SendEncrypted(message, port, ip, key, iv) {
  const cipher = EncodeDesCBC(JSON.stringify(message), key, iv);
  server.send(Buffer.from(iv.toString('base64') + '.' + cipher, 'utf8'), port, ip);
}

// Create a function that encodes a message using DES-CBC
function EncodeDesCBC(textToEncode, key, iv) {
  var cipher = crypto.createCipheriv('des-cbc', key, iv);
  var encrypted = cipher.update(textToEncode, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

// Create a function that decrypts a message using DES-CBC
function Decrypt(message) {
  const msgArr = message.toString('utf8').split('.');
  const iv = Buffer.from(msgArr[0], 'base64');
  const rsaEncryptedKey = Buffer.from(msgArr[1], 'base64');
  const encrypted = Buffer.from(msgArr[2], 'base64');
  const desKey = crypto.privateDecrypt(private_key, rsaEncryptedKey);
  const decrypted = crypto.createDecipheriv('des-cbc', desKey, iv);
  let d = decrypted.update(encrypted, 'base64', 'utf8');
  d += decrypted.final('utf8');
  return [d, desKey, iv];
}

server.on('listening', () => {
  console.log(`Server is listening on port: ${server.address().port}`);
});
