"""WM Technique 1 (from video)
    Encoder:
    Choose k, e, m and v are randomly selected and kept secret.
            k: secret key
            e: # least significant bits
            m: marker selection
            v: # attributes
    1. r.MAC = H(k||r.P)
    2. if(r.MAC mod m == 0)  // marker selection
    3. i = r.MAC mod v  // selected attributes
    4. b = r.MAC mod e  // selected LSB index
    5. if(r.MAC mod 2 == 0)
            set bit b of r.Ai
       else:
            clear bit b of r.Ai
"""

import os
import cmd
import sys
import hashlib
import sqlite3


class Encoder():
    def __init__(self):
        # connecting to the database
        db = sqlite3.connect("tobemarked.sqlite")

        # a cursor to move through rows
        self.cursor = db.cursor()
        self.cursor.execute("select * from tableA")
        list_of_tuples = self.cursor.fetchall()  # list of all tuples in a table
        # headers = list(map(lambda x: x[0], cursor.description))
        headers = [description[0] for description in self.cursor.description]

        self.e = 4  # number of LSBs to be altered
        list_of_pks = []  # list of primary keys in a table
        list_of_macs = []  # list of calculated MACs -> Hash(key||PKs)

        # generating a key and writing it to disk
        # key = os.urandom(16)
        # with open('./key.pem', 'wb') as secret_key:
        #     secret_key.write(key)

        # loading secret key from disk
        with open('./key.pem', 'rb') as secret_key:
            read_key = secret_key.read()
            print('Key: {}'.format(read_key))

        # calculate r.MAC (step 1) for each tuple
        for tup in list_of_tuples:
            primary_key = int(tup[0])

            HASH = hashlib.new('SHA1')
            HASH.update(read_key + bytes(primary_key))

            list_of_pks.append(primary_key)
            list_of_macs.append(int(HASH.hexdigest(), 16))  # store it as decimal

        print('List of primary keys: {}'.format(list_of_pks))
        print('List of calculated MACs: {}'.format(list_of_macs))

        chosen_tuples_pks = []  # PKs
        chosen_attributes = []  # attributes to alter
        corresponding_macs = []  # their MACs
        names_of_attributes = []  # their names (headers)

        # choosing tuples
        for i in range(len(list_of_tuples)):
            if list_of_macs[i] % list_of_pks[i] == 0:  # (step 2)
                # choosing attributes with numerical data (even columns)
                for j in range(2, len(list_of_tuples[0]), 2):
                    if list_of_macs[i] % j == 0:  # (step 3)
                        chosen_tuples_pks.append(list_of_pks[i])
                        corresponding_macs.append(list_of_macs[i])
                        chosen_attributes.append(int(list_of_tuples[i][j]))
                        names_of_attributes.append(headers[j])

        # marking and apply changes to the database
        self.mark(chosen_attributes, names_of_attributes, corresponding_macs, chosen_tuples_pks)

        self.cursor.close()

    def mark(self, numerical_attributes, columns, macs, pks):
        if len(numerical_attributes) > 0:
            print('Before marking: {}'.format(numerical_attributes))

            for i in range(len(numerical_attributes)):
                numerical_attributes[i] = [str(x) for x in bin(numerical_attributes[i])[2:]]

            for i in range(len(numerical_attributes)):
                b = macs[i] % self.e  # (step 4)
                index = (len(numerical_attributes[i]) - 1) - b
                if macs[i] % 2 == 0:  # (step 5)
                    numerical_attributes[i][index] = '1'
                else:
                    numerical_attributes[i][index] = '0'

            updated_attrs = []
            for i in numerical_attributes:
                updated_attrs.append(''.join(i))

            for i in range(len(updated_attrs)):
                updated_attrs[i] = int(updated_attrs[i], 2)

            self.apply(updated_attrs, columns, pks)
        else:
            print('No attributes to mark!')
            return None

    def apply(self, new_values, columns_names, primary_keys):
        index = 0
        length = len(new_values)

        while index < length:
            query = "update tableA set {} = {} where id = {}".format(columns_names[index], new_values[index],
                                                                     primary_keys[index])
            self.cursor.execute(query)
            index += 1

        self.cursor.connection.commit()
        print('Marking is completed!')


class Decoder():
    def __init__(self):
        # connecting to the database
        db = sqlite3.connect("tobemarked.sqlite")

        # a cursor to move through rows
        self.cursor = db.cursor()
        self.cursor.execute("select * from tableA")
        list_of_tuples = self.cursor.fetchall()  # list of all tuples in a table
        # headers = list(map(lambda x: x[0], cursor.description))
        headers = [description[0] for description in self.cursor.description]

        self.e = 4  # number of LSBs to be altered
        list_of_pks = []  # list of primary keys in a table
        list_of_macs = []  # list of calculated MACs -> Hash(key||PKs)

        # loading secret key from disk
        with open('./key.pem', 'rb') as secret_key:
            read_key = secret_key.read()
            print('Key: {}'.format(read_key))

        # calculate r.MAC (step 1) for each tuple
        for tup in list_of_tuples:
            primary_key = int(tup[0])

            HASH = hashlib.new('SHA1')
            HASH.update(read_key + bytes(primary_key))

            list_of_pks.append(primary_key)
            list_of_macs.append(int(HASH.hexdigest(), 16))  # store it as decimal

        print('List of primary keys: {}'.format(list_of_pks))
        print('List of calculated MACs: {}'.format(list_of_macs))

        chosen_tuples_pks = []  # PKs
        chosen_attributes = []  # attributes to alter
        corresponding_macs = []  # their MACs
        names_of_attributes = []  # their names (headers)

        # choosing tuples
        for i in range(len(list_of_tuples)):
            if list_of_macs[i] % list_of_pks[i] == 0:  # (step 2)
                # choosing attributes with numerical data (even columns)
                for j in range(2, len(list_of_tuples[0]), 2):
                    if list_of_macs[i] % j == 0:  # (step 3)
                        chosen_tuples_pks.append(list_of_pks[i])
                        corresponding_macs.append(list_of_macs[i])
                        chosen_attributes.append(int(list_of_tuples[i][j]))
                        names_of_attributes.append(headers[j])

        # unmarking and apply changes to the database
        self.unmark(chosen_attributes, names_of_attributes, corresponding_macs, chosen_tuples_pks)

        self.cursor.close()

    def unmark(self, numerical_attributes, columns, macs, pks):
        if len(numerical_attributes) > 0:

            for i in range(len(numerical_attributes)):
                numerical_attributes[i] = [str(x) for x in bin(numerical_attributes[i])[2:]]

            for i in range(len(numerical_attributes)):
                b = macs[i] % self.e  # (step 4)
                index = (len(numerical_attributes[i]) - 1) - b
                if macs[i] % 2 == 0:  # (step 5)
                    numerical_attributes[i][index] = '0'
                else:
                    numerical_attributes[i][index] = '1'

            updated_attrs = []
            for i in numerical_attributes:
                updated_attrs.append(''.join(i))

            for i in range(len(updated_attrs)):
                updated_attrs[i] = int(updated_attrs[i], 2)

            self.apply(updated_attrs, columns, pks)
        else:
            print('No attributes to unmark!')
            return None

    def apply(self, new_values, columns_names, primary_keys):
        index = 0
        length = len(new_values)

        while index < length:
            query = "update tableA set {} = {} where id = {}".format(
                columns_names[index], new_values[index], primary_keys[index])
            self.cursor.execute(query)
            index += 1

        self.cursor.connection.commit()
        print('Unmarking is completed!')


class TUI(cmd.Cmd):
    prompt = 'Marker0.1> '

    def __init__(self):
        super().__init__(completekey='Tab')

    def do_encode(self, arg):
        """Marks the database"""
        Encoder()

    def do_decode(self, arg):
        """Unmarks the database"""
        Decoder()

    def do_quit(self, arg):
        """quit exits the program"""
        sys.exit(0)


if __name__ == '__main__':
    TUI().cmdloop('-- Welcome to Marker 0.1 <? for help>\n')
