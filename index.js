const express = require('express');
const crypto = require('crypto');
const ethers = require('ethers');
const app = express();
const path = require("path");
const bodyParser = require("body-parser");
app.use(express.static(__dirname));
const jwt = require('jsonwebtoken');
app.use(express.json())
app.use(bodyParser.json());
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname + '/index.html'));
});
app.get('/api/nonce', (req, res) => {
  const nonce = crypto.randomBytes(32).toString('hex');
  res.json({ nonce });
});

const secretKey = 'mySecretKey';

app.post('/login', (req, res) => {
  const { signedMessage, message, address } = req.body;
  const recoveredAddress = ethers.utils.verifyMessage(message, signedMessage);
  if (recoveredAddress !== address) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  const token = jwt.sign({ address }, secretKey, { expiresIn: '10s' });
  console.log('Generated token:', token);
  res.json(token);
});

app.post('/verify', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header missing or invalid' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
      // Verify the JWT token
      const decoded = jwt.verify(token, secretKey);
      console.log('Decoded token:', decoded);
      const currentTime = Math.floor(Date.now() / 1000);
      console.log('Current time:', currentTime);
      if (decoded.exp < currentTime) {
          return res.json("tokenExpired");
      } else {
          return res.json("ok");
      }
  } catch (err) {
      console.error('Token verification error:', err);
      return res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname + '/success.html'));
});

app.listen(5500, () => {
  console.log('Server started on port 5500');
});