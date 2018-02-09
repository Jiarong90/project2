
class Login:
    def __init__(self, username):
        self.__username = username

    def set_username(self, username):
        self.__username = username

    def get_username(self):
        return self.__username