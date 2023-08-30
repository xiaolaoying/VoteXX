const express = require('express');
const path = require('path');
const app = express();
const PORT = 3300;

app.use(express.static('UI'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'UI/base.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
