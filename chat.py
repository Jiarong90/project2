class Chat:
    def __init__(self, message, username, chatnumber):
        self.__chatid = ''
        self.__message = message
        self.__username = username
        self.__chatnumber = chatnumber

    def set_message(self, message):
        self.__message = message

    def get_message(self):
        return self.__message

    def set_chatid(self, chatid):
        self.__chatid = chatid

    def get_chatid(self):
        return self.__chatid

    def set_username(self, username):
        self.__username = username

    def get_username(self):
        return self.__username

    def set_chatnumber(self, chatnumber):
        chatnumber += 1

    def get_chatnumber(self):
        return self.__chatnumber
