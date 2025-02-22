const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../public')));

// Placeholder for API requests
app.post('/api/register', (req, res) => {
  // Add your API request logic here
  console.log('Register request:', req.body);
  res.json({ status: 'success', data: true });
});

app.post('/api/login', (req, res) => {
  // Add your API request logic here
  console.log('Login request:', req.body);
  res.json({ status: 'success', data: { userroot_id: 'random_string' } });
});

app.listen(PORT, () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
});
