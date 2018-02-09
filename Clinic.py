import datetime


class Clinic:
    def __init__(self, title, address, phone, openingHour, busNo, mrtStation, hospital, created_by, areaName, region,
                 photo):
        self.__clinicid = ''
        self.__title = title
        self.__address = address
        self.__phone = phone
        self.__openingHour = openingHour
        self.__busNo = busNo
        self.__mrtStation = mrtStation
        self.__hospital = hospital
        currentdatetime = datetime.datetime.now()
        create_date = str(currentdatetime.day) + "-" + str(currentdatetime.month) + "-" + str(
            currentdatetime.year)  # DD-MM-YYYY format
        self.__created_date = create_date
        self.__created_by = created_by
        self.__areaName = areaName
        self.__region = region
        self.__photo = photo

    def get_clinicid(self):
        return self.__clinicid

    def get_title(self):
        return self.__title

    def get_address(self):
        return self.__address

    def get_phone(self):
        return self.__phone

    def get_openingHour(self):
        return self.__openingHour

    def get_busNo(self):
        return self.__busNo

    def get_mrtStation(self):
        return self.__mrtStation

    def get_hospital(self):
        return self.__hospital

    def get_areaName(self):
        return self.__areaName

    def get_region(self):
        return self.__region

    def get_photo(self):
        return self.__photo

    def get_created_by(self):
        return self.__created_by

    def get_created_date(self):
        return self.__created_date

    def set_title(self, title):
        self.__title = title

    def set_address(self, address):
        self.__address = address

    def set_phone(self, phone):
        self.__phone = phone

    def set_openingHour(self, openingHour):
        self.__openingHour = openingHour

    def set_busNo(self, busNo):
        self.__busNo = busNo

    def set_mrtStation(self, mrtStation):
        self.__mrtStation = mrtStation

    def set_hospital(self, hospital):
        self.__hospital = hospital

    def set_clinicid(self, clinicid):
        self.__clinicid = clinicid

    def set_areaName(self, areaName):
        self.__areaName = areaName

    def set_region(self, region):
        self.__region = region

    def set_photo(self, photo):
        self.__photo = photo

    def set_created_by(self, created_by):
        self.__createdby = created_by

    def set_created_date(self, created_date):
        self.__created_date = created_date



        # def __init__(self, title, publisher,  status, created_by, category, type):
        #        self.__pubid = ''
        #        self.__title = title
        #        self.__publisher = publisher
        #        self.__status = status
        #        self.__created_by = created_by
        #        currentdatetime = datetime.datetime.now()
        #        create_date = str(currentdatetime.day) + "-" + str(currentdatetime.month) + "-" + str(
        #            currentdatetime.year)  # DD-MM-YYYY format
        #        self.__created_date = create_date
        #        self.__category = category
        #        self.__type = type
        #
        #    def get_title(self):
        #        return self.__title
        #
        #    def get_publisher(self):
        #        return self.__publisher
        #
        #    def get_status(self):
        #        return self.__status
        #
        #    def get_created_by(self):
        #        return self.__created_by
        #
        #    def get_created_date(self):
        #        return self.__created_date
        #
        #    def get_category(self):
        #        return self.__category
        #
        #    def get_type(self):
        #        return self.__type
        #
        #    def set_title(self, title):
        #        self.__title = title
        #
        #    def set_publisher(self, publisher):
        #        self.__publisher = publisher
        #
        #    def set_status(self, status):
        #        self.__status = status
        #
        #    def set_created_by(self, created_by):
        #        self.__created_by = created_by
        #
        #    def set_created_date(self, create_date):
        #        self.__created_date = create_date
        #
        #    def set_category(self, category):
        #        self.__category = category
        #
        #    def set_type(self, type):
        #        self.__type = type
        #
        #    def get_pubid(self):
        #        return self.__pubid
        #
        #    def set_pubid(self, pubid):
        #        self.__pubid = pubid
