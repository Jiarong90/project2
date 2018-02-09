from Publication import booking


class Magazine(booking):

    def __init__(self, title, publisher, status, created_by, category, type, frequency):
        booking.__init__(self, title, publisher, status, created_by, category, type)
        self.__frequency = frequency

    def get_frequency(self):
        return self.__frequency

    def set_frequency(self, frequency):
        self.__frequency = frequency

    def add(self, amag):
        pass

    def update(self, amag):
        pass

    def delete(self, id):
        pass

    def retrieve_a_mag(self, id):
        pass

    def retrieve_all_mag(self):
        pass



