import { API, render, showError } from './utils.js';

export class AuthManager {
    constructor() {
        this.api = new API();
        this.checkAuth();
    }

    async checkAuth() {
        const token = localStorage.getItem('userroot_id');
        const username = localStorage.getItem('username');

        if (token && username) {
            try {
                await this.api.request('POST', '/api/v1/authcheck', { username, userroot_id: token });
                this.redirectToMain();
            } catch {
                localStorage.clear();
            }
        }
    }

    async handleLogin(username, password) {
        try {
            const result = await this.api.request('POST', '/api/v1/users/login', { username, password });
            localStorage.setItem('userroot_id', result.userroot_id);
            localStorage.setItem('username', username);
            this.redirectToMain();
        } catch (error) {
            showError(error.message);
        }
    }

    async handleRegister(username, password) {
        try {
            await this.api.request('POST', '/api/v1/users/register', { username, password });
            showError('注册成功，请登录');
            window.location.href = '/';
        } catch (error) {
            showError(error.message);
        }
    }

    redirectToMain() {
        window.location.href = '/main.html';
    }
}
