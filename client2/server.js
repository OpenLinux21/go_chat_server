const express = require('express');
const morgan = require('morgan');
const path = require('path');
const app = express();
const port = 3000;

// 增强的日志格式
app.use(morgan(':date[iso] :method :url :status :res[content-length] - :response-time ms'));

// 静态文件服务
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// 全局错误处理
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
});

// 前端路由处理
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Frontend server running at http://localhost:${port}`);
});
