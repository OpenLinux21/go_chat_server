import { AuthManager } from './auth.js';
import { FriendsManager } from './friends.js';
import { ChatManager } from './chat.js';
import { render } from './utils.js';

class ChatApp {
    constructor() {
        this.auth = new AuthManager();
        this.friendsManager = new FriendsManager();
        this.chatManager = new ChatManager();
        this.initRoutes();
        this.initErrorHandling();

    }

      initErrorHandling() {
        // 全局错误捕获
        window.addEventListener('error', (event) => {
            console.error('Global Error:', event.error);
            this.showError(`系统错误: ${event.error.message}`);
        });

        // Promise rejection 捕获
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled Rejection:', event.reason);
            this.showError(`操作失败: ${event.reason.message}`);
        });

        // 网络状态监控
        window.addEventListener('offline', () => {
            this.showError('网络连接已断开');
        });

        window.addEventListener('online', () => {
            this.showError('网络连接已恢复');
        });
    }

    initRoutes() {
        const path = window.location.pathname;

        if (path === '/main.html') {
            this.renderMain();
        } else if (path === '/register.html') {
            this.renderRegister();
        } else {
            this.renderLogin();
        }
    }

    renderLogin() {
        const app = document.getElementById('app');
        app.appendChild(render(`
            <div class="auth-page">
                <div class="auth-box">
                    <h2 class="text-center mb-4">用户登录</h2>
                    <form id="loginForm">
                        <input type="text" class="form-control mb-3" placeholder="用户名" required>
                        <input type="password" class="form-control mb-3" placeholder="密码" required>
                        <button class="btn btn-primary w-100">登录</button>
                    </form>
                    <div class="text-center mt-3">
                        <a href="/register.html">注册新账号</a>
                    </div>
                </div>
            </div>
        `));

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            await this.auth.handleLogin(username, password);
        });
    }

    async renderMain() {
        const app = document.getElementById('app');
        app.appendChild(this.chatManager.renderChatInterface());

        // 加载好友列表
        const friends = await this.friendsManager.getFriendsList(localStorage.getItem('username'));
        document.querySelector('.sidebar').appendChild(this.friendsManager.renderFriendsList(friends));

        // 初始化聊天功能
        document.querySelector('.send-btn').addEventListener('click', () => {
            const input = document.querySelector('.message-input input');
            this.chatManager.sendMessage(input.value);
            input.value = '';
        });

        // 文件上传处理
        document.querySelector('.upload-btn').addEventListener('click', () => {
            document.getElementById('file-upload').click();
        });

        document.getElementById('file-upload').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (file.size > 128 * 1024 * 1024) {
                showError('文件大小超过限制');
                return;
            }

            const progressBar = document.querySelector('.file-upload-bar');
            const progressContainer = document.querySelector('.file-upload-progress');
            progressContainer.classList.remove('d-none');

            try {
                await this.chatManager.api.handleFileUpload(
                    `/api/v2/chats/private/${this.chatManager.currentChat.uuid}/files`,
                    file,
                    (percent) => {
                        progressBar.style.width = `${percent}%`;
                    }
                );
            } finally {
                progressContainer.classList.add('d-none');
            }
        });
    }

    renderRegister() {
        const app = document.getElementById('app');
        app.appendChild(render(`
            <div class="auth-page">
                <div class="auth-box">
                    <h2 class="text-center mb-4">用户注册</h2>
                    <form id="registerForm">
                        <input type="text" class="form-control mb-3" placeholder="用户名" required>
                        <input type="password" class="form-control mb-3" placeholder="密码" required>
                        <button class="btn btn-primary w-100">注册</button>
                    </form>
                    <div class="text-center mt-3">
                        <a href="/">已有账号？立即登录</a>
                    </div>
                </div>
            </div>
        `));

        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            await this.auth.handleRegister(username, password);
        });
    }
}

// 初始化应用
new ChatApp();
