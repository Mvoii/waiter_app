MOCK_USERS = [{ "test@example.com":"12345", "salt": "8Fb23mMNHD5Zb8pr2qWA3PE9bH0=", "hashed":
'1736f83698df3f8153c1fbd6ce2840f8aace4f200771a46672635374073cc876c"f0aa6a31f780e576578f791b5555b50df46303f0c3a7f2d21f91aa1429ac22e'}]

class MockDBHelper:
    
    def get_user(self, email):
        # if email in MOCK_USERS:
        user = [x for x in MOCK_USERS if x.get("email") == email]
        if user:
            return user[0]
        return None
            # return MOCK_USERS[email]
        # return None
        
    def add_user(self, email, salt, hashed):
            MOCK_USERS.append({"email": email, "salt": salt, "hashed": hashed})