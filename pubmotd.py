
class healthtips:

    def __init__(self, title, description):
        self.__pubid = ''
        self.__title = title
        self.__description = description

    def get_title(self):
        return self.__title

    def set_title(self, title):
        self.__title = title

    def get_pubid(self):
        return self.__pubid

    def set_pubid(self, pubid):
        self.__pubid = pubid

    def get_description(self):
        return self.__description

    def set_description(self, description):
        self.__description = description


