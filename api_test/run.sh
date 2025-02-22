#!/bin/bash
# test_api.sh
# 用于一次性测试所有 API 功能，运行完后输出工作不正常的 API 列表

BASE_URL="http://localhost:8011"
FAILURES=()

# 简单封装测试函数
# 参数1：测试名称
# 参数2：curl 命令（字符串），必须返回 JSON 格式数据，其中 "status" 字段为 "success" 表示成功
run_test() {
    local test_name="$1"
    local curl_cmd="$2"
    echo "Running test: $test_name"
    result=$(eval $curl_cmd)
    status=$(echo "$result" | jq -r '.status')
    if [ "$status" != "success" ]; then
       echo "Test [$test_name] failed: $result"
       FAILURES+=("$test_name")
    else
       echo "Test [$test_name] passed."
    fi
    echo ""
}

# 为文件上传测试创建临时文件
echo "Hello, this is a test file" > testfile.txt

# 1. 注册两个测试用户：testuser 和 testuser2
run_test "User Registration - testuser" "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\": \"testuser\", \"password\": \"TestPass123!\"}' $BASE_URL/api/v1/users/register"
run_test "User Registration - testuser2" "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\": \"testuser2\", \"password\": \"TestPass123!\"}' $BASE_URL/api/v1/users/register"

# 2. testuser 登录
echo "Logging in testuser..."
LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username": "testuser", "password": "TestPass123!"}' $BASE_URL/api/v1/users/login)
LOGIN_STATUS=$(echo "$LOGIN_RESPONSE" | jq -r '.status')
if [ "$LOGIN_STATUS" != "success" ]; then
    echo "Login testuser failed: $LOGIN_RESPONSE"
    FAILURES+=("User Login - testuser")
else
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.userroot_id')
    echo "testuser token: $TOKEN"
fi
echo ""

# 3. 获取 testuser 个人信息
run_test "Get Profile - testuser" "curl -s -X GET \"$BASE_URL/api/v1/users/profile?username=testuser\" -H 'Authorization: Bearer $TOKEN'"

# 4. 更新 testuser 个人信息 (设置 mode 为 busy)
run_test "Update Profile - testuser" "curl -s -X PUT -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"mode\": \"busy\"}' $BASE_URL/api/v1/users/profile"

# 5. 验证 testuser 认证状态
run_test "Auth Check - testuser" "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\": \"testuser\", \"userroot_id\": \"$TOKEN\"}' $BASE_URL/api/v1/authcheck"

# 6. Token 刷新
REFRESH_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"userroot_id\": \"$TOKEN\"}" $BASE_URL/api/v1/token/refresh)
REFRESH_STATUS=$(echo "$REFRESH_RESPONSE" | jq -r '.status')
if [ "$REFRESH_STATUS" != "success" ]; then
    echo "Token refresh failed: $REFRESH_RESPONSE"
    FAILURES+=("Token Refresh - testuser")
else
    NEW_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.userroot_id')
    echo "New token: $NEW_TOKEN"
    TOKEN=$NEW_TOKEN
fi
echo ""

# 7. 修改 testuser 密码（保持不变）
run_test "Change Password - testuser" "curl -s -X PUT -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"username\": \"testuser\", \"old_password\": \"TestPass123!\", \"new_password\": \"TestPass123!\"}' $BASE_URL/api/v1/users/password"

# 8. 获取 testuser2 的信息以取得 user_id
PROFILE2=$(curl -s -X GET "$BASE_URL/api/v1/users/profile?username=testuser2")
PROFILE2_STATUS=$(echo "$PROFILE2" | jq -r '.status')
if [ "$PROFILE2_STATUS" != "success" ]; then
    echo "Get profile testuser2 failed: $PROFILE2"
    FAILURES+=("Get Profile - testuser2")
else
    USER2_ID=$(echo "$PROFILE2" | jq -r '.data.user_id')
    echo "testuser2 user id: $USER2_ID"
fi
echo ""

# 9. testuser 添加 testuser2 为好友
run_test "Add Friend - testuser -> testuser2" "curl -s -X POST -H 'Authorization: Bearer $TOKEN' -d 'target_user_id=$USER2_ID' $BASE_URL/api/v1/testuser/friends"

# 10. testuser 删除好友 testuser2
run_test "Delete Friend - testuser -> testuser2" "curl -s -X DELETE -H 'Authorization: Bearer $TOKEN' -d 'target_user_id=$USER2_ID' $BASE_URL/api/v1/testuser/friends"

# 11. 发送好友请求 (testuser -> testuser2)
run_test "Send Friend Request - testuser -> testuser2" "curl -s -X POST -H 'Authorization: Bearer $TOKEN' -d 'target_user_id=$USER2_ID' $BASE_URL/api/v1/testuser/friends/request"

# 12. testuser2 登录
echo "Logging in testuser2..."
LOGIN_RESPONSE2=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username": "testuser2", "password": "TestPass123!"}' $BASE_URL/api/v1/users/login)
LOGIN_STATUS2=$(echo "$LOGIN_RESPONSE2" | jq -r '.status')
if [ "$LOGIN_STATUS2" != "success" ]; then
    echo "Login testuser2 failed: $LOGIN_RESPONSE2"
    FAILURES+=("User Login - testuser2")
else
    TOKEN2=$(echo "$LOGIN_RESPONSE2" | jq -r '.data.userroot_id')
    echo "testuser2 token: $TOKEN2"
fi
echo ""

# 13. testuser2 处理好友请求（这里使用 request_id 为 1 作示例，实际中应获取正确 id）
run_test "Handle Friend Request (reject dummy) - testuser2" "curl -s -X PUT -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN2' -d '{\"request_id\": 1, \"action\": \"reject\"}' $BASE_URL/api/v1/testuser2/friends/request"

# 14. 创建私聊会话 (testuser -> testuser2)
CHAT_UUID=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -d "target_user_id=$USER2_ID" $BASE_URL/api/v2/chats/private | jq -r '.data')
if [ -z "$CHAT_UUID" ]; then
    echo "Create private chat failed."
    FAILURES+=("Create Private Chat")
else
    echo "Private chat uuid: $CHAT_UUID"
fi
echo ""

# 15. 发送私聊消息
run_test "Send Private Message" "curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"message\": \"Hello, this is a test message.\"}' $BASE_URL/api/v2/chats/private/$CHAT_UUID/messages"

# 16. 获取私聊消息
run_test "Get Private Messages" "curl -s -X GET -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v2/chats/private/$CHAT_UUID/messages"

# 17. 发送私聊文件
run_test "Send Private File" "curl -s -X POST -H 'Authorization: Bearer $TOKEN' -F 'file=@testfile.txt' $BASE_URL/api/v2/chats/private/$CHAT_UUID/files"

# 18. 获取私聊文件列表
run_test "Get Private Files" "curl -s -X GET -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v2/chats/private/$CHAT_UUID/files"

# 19. 创建群聊 (包含 testuser2)
GROUP_UUID=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -F "groupName=TestGroup" -F "members=$USER2_ID" $BASE_URL/api/v2/chats/groups | jq -r '.data')
if [ -z "$GROUP_UUID" ]; then
    echo "Create group chat failed."
    FAILURES+=("Create Group Chat")
else
    echo "Group chat uuid: $GROUP_UUID"
fi
echo ""

# 20. 修改群聊名称
run_test "Update Group Name" "curl -s -X PUT -H 'Authorization: Bearer $TOKEN' -F 'new_groupName=NewTestGroup' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/name"

# 21. 获取群聊成员列表
run_test "Get Group Members" "curl -s -X GET -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/members"

# 22. 发送群聊消息
run_test "Send Group Message" "curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"message\": \"Hello group!\"}' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/messages"

# 23. 获取群聊消息
run_test "Get Group Messages" "curl -s -X GET -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/messages"

# 24. 发送群聊文件
run_test "Send Group File" "curl -s -X POST -H 'Authorization: Bearer $TOKEN' -F 'file=@testfile.txt' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/files"

# 25. 获取群聊文件列表
run_test "Get Group Files" "curl -s -X GET -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v2/chats/groups/$GROUP_UUID/files"

# 清理临时文件
rm testfile.txt

echo ""
if [ ${#FAILURES[@]} -eq 0 ]; then
    echo "All API tests passed successfully."
else
    echo "The following API tests failed:"
    for test in "${FAILURES[@]}"; do
        echo "- $test"
    done
fi

