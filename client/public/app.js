// API 服务器地址更新为 127.0.0.1:8011
const API_BASE = 'http://192.168.2.61:8011';

let currentUser = null;         // 当前登录用户名
let userToken = null;           // 登录后获得的 token (userroot_id)
let currentChatSession = null;  // 当前私聊会话的 uuid
let currentChatFriend = null;   // 当前聊天对象（{ user_id, username }）
let messageTimer = null;        // 消息轮询定时器

// 日志上报函数：将日志发送到 /log 接口
function reportLog(message) {
  fetch('/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log: message })
  }).catch(err => console.error('日志上报失败:', err));
}

// 日志输出函数：在 Console、页面日志面板输出，同时上报到服务器
function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  const logMessage = `[${timestamp}] ${message}`;
  console.log(logMessage);
  reportLog(logMessage);
  const logContent = document.getElementById('log-content');
  if (logContent) {
    const p = document.createElement('p');
    p.innerText = logMessage;
    logContent.appendChild(p);
    logContent.scrollTop = logContent.scrollHeight;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  // 切换登录/注册表单
  document.getElementById('show-register').addEventListener('click', (e) => {
    e.preventDefault();
    log('切换到注册表单');
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
  });
  document.getElementById('show-login').addEventListener('click', (e) => {
    e.preventDefault();
    log('切换到登录表单');
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
  });

  // 按钮事件绑定
  document.getElementById('login-btn').addEventListener('click', login);
  document.getElementById('register-btn').addEventListener('click', register);
  document.getElementById('logout-btn').addEventListener('click', logout);
  document.getElementById('send-btn').addEventListener('click', sendMessage);
  document.getElementById('add-friend-btn').addEventListener('click', addFriend);
});

/** 用户注册 */
async function register() {
  const username = document.getElementById('register-username').value.trim();
  const password = document.getElementById('register-password').value.trim();
  if (!username || !password) {
    alert('请输入用户名和密码');
    return;
  }
  log(`尝试注册：用户名=${username}`);
  try {
    const res = await fetch(`${API_BASE}/api/v1/users/register`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const result = await res.json();
    if (result.status === 'success') {
      log('注册成功');
      alert('注册成功，请登录');
      document.getElementById('register-form').style.display = 'none';
      document.getElementById('login-form').style.display = 'block';
    } else {
      log(`注册失败：${result.message || result.code}`);
      alert(`注册失败：${result.message || result.code}`);
    }
  } catch (error) {
    log(`注册请求出错：${error}`);
    console.error(error);
    alert('注册请求出错');
  }
}

/** 用户登录 */
async function login() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value.trim();
  if (!username || !password) {
    alert('请输入用户名和密码');
    return;
  }
  log(`尝试登录：用户名=${username}`);
  try {
    const res = await fetch(`${API_BASE}/api/v1/users/login`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const result = await res.json();
    if (result.status === 'success') {
      userToken = result.data.userroot_id;
      currentUser = username;
      log(`登录成功，Token=${userToken}`);
      switchToChat();
      loadFriends();
    } else {
      log(`登录失败：${result.message || result.code}`);
      alert(`登录失败：${result.message || result.code}`);
    }
  } catch (error) {
    log(`登录请求出错：${error}`);
    console.error(error);
    alert('登录请求出错');
  }
}

/** 退出登录 */
function logout() {
  log('用户退出登录');
  currentUser = null;
  userToken = null;
  currentChatSession = null;
  currentChatFriend = null;
  clearInterval(messageTimer);
  document.getElementById('chat-container').style.display = 'none';
  document.getElementById('auth-container').style.display = 'block';
}

/** 切换到聊天界面 */
function switchToChat() {
  log('切换到聊天界面');
  document.getElementById('auth-container').style.display = 'none';
  document.getElementById('chat-container').style.display = 'block';
  document.getElementById('chat-target').innerText = '无';
  document.getElementById('messages').innerHTML = '';
}

/** 加载好友列表 */
async function loadFriends() {
  log('加载好友列表');
  try {
    const res = await fetch(`${API_BASE}/api/v1/${currentUser}/friends`, {
      method: 'GET',
      mode: 'cors',
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    const result = await res.json();
    if (result.status === 'success') {
      log('好友列表加载成功');
      renderFriendList(result.data);
    } else {
      log('加载好友列表失败');
      alert('加载好友列表失败');
    }
  } catch (error) {
    log(`加载好友列表请求出错：${error}`);
    console.error(error);
    alert('请求好友列表出错');
  }
}

/** 渲染好友列表 */
function renderFriendList(friends) {
  const list = document.getElementById('friends');
  list.innerHTML = '';
  if (friends.length === 0) {
    list.innerHTML = '<li>暂无好友</li>';
    log('当前没有好友');
    return;
  }
  friends.forEach(friend => {
    const li = document.createElement('li');
    li.innerText = friend.username;
    li.dataset.userId = friend.user_id;
    li.addEventListener('click', () => {
      log(`选择好友进行私聊：${friend.username} (ID: ${friend.user_id})`);
      startPrivateChat(friend);
    });
    list.appendChild(li);
  });
}

/** 添加好友 */
async function addFriend() {
  const targetUserId = document.getElementById('friend-id-input').value.trim();
  if (!targetUserId) {
    alert('请输入好友的用户ID');
    return;
  }
  log(`尝试发送好友请求，目标用户ID=${targetUserId}`);
  try {
    const formData = new FormData();
    formData.append('target_user_id', targetUserId);
    const res = await fetch(`${API_BASE}/api/v1/${currentUser}/friends/request`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Authorization': `Bearer ${userToken}` },
      body: formData
    });
    const result = await res.json();
    if (result.status === 'success') {
      log('好友请求发送成功');
      alert('好友请求已发送');
      loadFriends();
    } else {
      log(`好友请求发送失败：${result.message || result.code}`);
      alert(`好友请求发送失败：${result.message || result.code}`);
    }
  } catch (error) {
    log(`发送好友请求出错：${error}`);
    console.error(error);
    alert('发送好友请求出错');
  }
}

/** 发起私聊 */
async function startPrivateChat(friend) {
  currentChatFriend = friend;
  document.getElementById('chat-target').innerText = friend.username;
  log(`发起私聊，目标用户：${friend.username} (ID: ${friend.user_id})`);
  try {
    const formData = new FormData();
    formData.append('target_user_id', friend.user_id);
    const res = await fetch(`${API_BASE}/api/v2/chats/private`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Authorization': `Bearer ${userToken}` },
      body: formData
    });
    const result = await res.json();
    if (result.status === 'success') {
      currentChatSession = result.data;
      log(`私聊会话创建成功，uuid=${currentChatSession}`);
      loadMessages();
      if (messageTimer) clearInterval(messageTimer);
      messageTimer = setInterval(loadMessages, 3000);
    } else {
      log(`创建聊天会话失败：${result.message || result.code}`);
      alert('创建聊天会话失败');
    }
  } catch (error) {
    log(`发起私聊请求出错：${error}`);
    console.error(error);
    alert('发起私聊请求出错');
  }
}

/** 发送消息 */
async function sendMessage() {
  const messageText = document.getElementById('message-text').value.trim();
  if (!messageText || !currentChatSession) return;
  log(`发送消息：${messageText}`);
  try {
    const res = await fetch(`${API_BASE}/api/v2/chats/private/${currentChatSession}/messages`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ message: messageText })
    });
    const result = await res.json();
    if (result.status === 'success') {
      log('消息发送成功');
      document.getElementById('message-text').value = '';
      loadMessages();
    } else {
      log(`发送消息失败：${result.message || result.code}`);
      alert('发送消息失败');
    }
  } catch (error) {
    log(`发送消息请求出错：${error}`);
    console.error(error);
    alert('发送消息请求出错');
  }
}

/** 拉取当前聊天会话的消息记录 */
async function loadMessages() {
  if (!currentChatSession) return;
  log('拉取聊天记录');
  try {
    const res = await fetch(`${API_BASE}/api/v2/chats/private/${currentChatSession}/messages`, {
      method: 'GET',
      mode: 'cors',
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    const result = await res.json();
    if (result.status === 'success') {
      log('聊天记录拉取成功');
      renderMessages(result.data);
    } else {
      log(`拉取聊天记录失败：${result.message || result.code}`);
    }
  } catch (error) {
    log(`拉取聊天记录请求出错：${error}`);
    console.error(error);
  }
}

/** 渲染消息记录 */
function renderMessages(messages) {
  const messagesDiv = document.getElementById('messages');
  messagesDiv.innerHTML = '';
  messages.forEach(msg => {
    const div = document.createElement('div');
    div.className = 'message';
    // 简单区分自己与对方消息（假设 msg.sender 包含发送者用户名）
    if (msg.sender === currentUser) {
      div.style.textAlign = 'right';
      div.style.backgroundColor = '#d1e7dd';
    }
    div.innerText = msg.message;
    messagesDiv.appendChild(div);
  });
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
