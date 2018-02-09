class Monitoring:

    def __init__(self, name, status):
        self.__bookid = ''
        self.__name = name
        self.__status = status

    def set_name(self, name):
        self.__name = name

    def get_name(self):
        return self.__name

    def set_status(self, status):
        self.__status = status

    def get_status(self):
        return self.__status

    def set_bookid(self, bookid):
        self.__bookid = bookid

    def get_bookid(self):
        return self.__bookid