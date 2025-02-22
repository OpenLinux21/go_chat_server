import { API, render, showError } from './utils.js';

export class ChatManager {
    constructor() {
        this.api = new API();
        this.socket = null;
        this.currentChat = null;
    }

    async createPrivateChat(targetUserId) {
        try {
            this.currentChat = await this.api.request('POST', '/api/v2/chats/private',
                { target_user_id: targetUserId }, true);
            this.connectWebSocket();
            return this.currentChat.uuid;
        } catch (error) {
            showError('创建会话失败');
        }
    }

    connectWebSocket() {
        this.socket = new WebSocket(`ws://127.0.0.1:8011/ws?token=${localStorage.getItem('userroot_id')}`);

        this.socket.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.appendMessage(message);
        };

        this.socket.onclose = () => {
            setTimeout(() => this.connectWebSocket(), 5000);
        };
    }

    async sendMessage(content) {
        try {
            await this.api.request('POST',
                `/api/v2/chats/private/${this.currentChat.uuid}/messages`,
                { message: content });
        } catch (error) {
            showError('发送消息失败');
        }
    }

    async loadHistory(uuid, limit = 50) {
        try {
            return await this.api.request('GET',
                `/api/v2/chats/private/${uuid}/history?limit=${limit}`);
        } catch (error) {
            showError('加载历史消息失败');
            return [];
        }
    }

    appendMessage(message) {
        const messagesContainer = document.querySelector('.message-list');
        const messageEl = render(`
            <div class="message-item">
                <div class="message-header">
                    <strong>${message.sender}</strong>
                    <small>${new Date(message.timestamp).toLocaleTimeString()}</small>
                </div>
                <div class="message-content">${message.content}</div>
            </div>
        `);
        messagesContainer.appendChild(messageEl);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    renderChatInterface() {
        return render(`
            <div class="chat-container">
                <div class="sidebar">
                    <!-- 好友列表 -->
                </div>
                <div class="chat-main">
                    <div class="message-list"></div>
                    <div class="message-input p-2 border-top">
                        <div class="input-group">
                            <input type="text" class="form-control" placeholder="输入消息...">
                            <button class="btn btn-primary send-btn">发送</button>
                            <input type="file" class="d-none" id="file-upload">
                            <button class="btn btn-secondary upload-btn">上传文件</button>
                        </div>
                        <div class="file-upload-progress d-none">
                            <div class="file-upload-bar" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>
        `);
    }
}
