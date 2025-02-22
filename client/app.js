const express = require('express');
const path = require('path');
const morgan = require('morgan');
const app = express();
const port = process.env.PORT || 3000;

// 使用 morgan 输出详细请求日志
app.use(morgan('dev'));

// 解析 JSON 请求体
app.use(express.json());

// 提供静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 日志上报接口：客户端将日志 POST 到此接口，服务器终端会输出
app.post('/log', (req, res) => {
  console.log(`[客户端日志] ${req.body.log}`);
  res.sendStatus(200);
});

// 首页
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// 启动服务
app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
