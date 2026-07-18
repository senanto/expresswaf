const express = require('express');
const { waf } = require('@expresswaf/expresswaf');

const app = express();
app.use(express.json());
app.use(waf());

app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
