import { API, render, showError } from './utils.js';

export class FriendsManager {
    constructor() {
        this.api = new API();
    }

    async getFriendsList(username) {
        try {
            return await this.api.request('GET', `/api/v1/${username}/friends`);
        } catch (error) {
            showError('获取好友列表失败');
            return [];
        }
    }

    async addFriend(targetUserId) {
        try {
            await this.api.request('POST', `/api/v1/${localStorage.getItem('username')}/friends`,
                { target_user_id: targetUserId }, true);
            return true;
        } catch (error) {
            showError('添加好友失败');
            return false;
        }
    }

    async removeFriend(targetUserId) {
        try {
            await this.api.request('DELETE', `/api/v1/${localStorage.getItem('username')}/friends`,
                { target_user_id: targetUserId }, true);
            return true;
        } catch (error) {
            showError('移除好友失败');
            return false;
        }
    }

    renderFriendsList(friends) {
        return render(`
            <div class="friends-list">
                ${friends.map(friend => `
                    <div class="friend-item d-flex align-items-center p-2">
                        <div class="me-auto">
                            ${friend.username}
                            <span class="online-status ${friend.mode || 'offline'}"></span>
                        </div>
                        <button class="btn btn-sm btn-danger remove-btn" data-id="${friend.user_id}">移除</button>
                    </div>
                `).join('')}
            </div>
        `);
    }
}
