from Publication import booking


class Book(booking):
    def __init__(self, title, publisher, status, created_by, category, type, synopsis, author, isbnno, patient_status):
        booking.__init__(self, title, publisher, status, created_by, category, type,)
        self.__synopsis = synopsis
        self.__author = author
        self.__isbnno = isbnno
        self.__patient_status = patient_status
    #getters

    def get_synopsis(self):
        return self.__synopsis

    def get_author(self):
        return self.__author

    def get_isbnno(self):
        return self.__author

    def get_patient_status(self):
        return self.__patient_status
    #setters

    def set_synopsis(self, synopsis):
        self.__synopsis = synopsis

    def set_author(self, author):
        self.__author = author

    def set_isbnno(self, isbnno):
        self.__isbnno = isbnno

    def set_patient_status(self, patient_status):
        self.__patient_status = patient_status

    def add(self):
        pass

    def update(self):
        pass