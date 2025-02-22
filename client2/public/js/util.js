export class API {
    constructor() {
        this.baseURL = 'http://127.0.0.1:8011';
        this.token = localStorage.getItem('userroot_id');
        this.debug = true; // 调试模式开关
    }

    _log(type, ...args) {
        if (this.debug) {
            const timestamp = new Date().toISOString();
            console[type](`[API][${timestamp}]`, ...args);
        }
    }

    async request(method, endpoint, data = null, isFormData = false) {
        const url = `${this.baseURL}${endpoint}`;
        const requestId = Math.random().toString(36).slice(2, 11);
        const headers = {};

        this._log('info', `[${requestId}] Starting ${method} ${url}`);

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
            this._log('debug', `[${requestId}] Using token: ${this.token.substr(0, 8)}...`);
        }

        const options = {
            method,
            headers,
            mode: 'cors',
            credentials: 'same-origin'
        };

        if (data) {
            if (isFormData) {
                options.body = data;
                this._log('debug', `[${requestId}] FormData:`, Array.from(data.entries()));
            } else {
                headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(data);
                this._log('debug', `[${requestId}] Request Body:`, data);
            }
        }

        try {
            const startTime = Date.now();
            const response = await fetch(url, options);
            const latency = Date.now() - startTime;

            this._log('info', `[${requestId}] Response ${response.status} in ${latency}ms`);

            if (!response.ok) {
                this._log('error', `[${requestId}] HTTP Error: ${response.statusText}`);
                throw new Error(`HTTP Error: ${response.status}`);
            }

            const result = await response.json();
            this._log('debug', `[${requestId}] Response Data:`, result);

            if (result.status === 'error') {
                this._log('error', `[${requestId}] API Error: ${result.code} - ${result.message}`);
                throw new Error(result.message);
            }

            return result.data;
        } catch (error) {
            this._log('error', `[${requestId}] Request Failed:`, error);
            throw error;
        }
    }

    // 其他方法保持不变...
}
