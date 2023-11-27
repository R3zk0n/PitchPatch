import sqlite3
import os
import struct

import requests
from bs4 import BeautifulSoup
from threading import Thread

from Utils.Utils import convert_date_format
import threading
from Utils.Utils import remove_namespace_prefix
# Collector Class
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import QueuePool
from sqlalchemy.ext.declarative import declarative_base
from bs4 import BeautifulSoup
import requests

db_semaphore = threading.Semaphore(1)
Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    title = Column(String)
    cve = Column(String, unique=True)
    description = Column(String)
    faq = Column(String)
    notes = relationship('Note')
    products = relationship('Product')
    threats = relationship('Threat')
    month = Column(String)

class Note(Base):
    __tablename__ = 'notes'

    id = Column(Integer, primary_key=True)
    cve = Column(String, ForeignKey('vulnerabilities.cve'))
    type = Column(String)
    title = Column(String)
    content = Column(String)

class Product(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key=True)
    product_id = Column(Integer)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))

class Threat(Base):
    __tablename__ = 'threats'

    id = Column(Integer, primary_key=True)
    type = Column(String)
    description = Column(String)
    product_id = Column(Integer)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))

class Collector:
    def __init__(self):
        self.url = 'https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/'
        self.engine = create_engine('sqlite:///cvrf_database.db', poolclass=QueuePool, pool_size=10)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        DB_Class = DatabaseClass()

    def process_vulnerability(self, child):
        cve = child.find('CVE')
        title = child.find('Title')
        description = child.find('Description')
        faq = child.find('FAQ')

        if cve is not None:
            cve_value = cve.text
            print(cve_value)
            print(title.text if title else None)
            print(description.text if description else None)
            print(faq.text if faq else None)

            # Check if the record with the same CVE value exists
            if not self.DB_Class.record_exists(cve_value):
                # Create a dictionary with the key-value pairs
                vuln_data = {
                    'title': title.text if title else None,
                    'cve': cve_value,
                    'description': description.text if description else None,
                    'faq': faq.text if faq else None
                }
                # Add the record to the database
                self.DB_Class.add_record(vuln_data)
            else:
                print(f"Record already exists for CVE: {cve_value}")

    def query_cvrf(self, date):
        try:
            # Convert the input date to the desired format
            cvrf_date = convert_date_format(date)
            print(cvrf_date)
            DB_Class = DatabaseClass()



            url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{cvrf_date}"
            req = requests.get(url)
            req.raise_for_status()  # Raise an exception if the request fails

            # Check if the response contains data
            if req.text:
                # Extract the Description by finding CVE and then locating the Description Note
                soup = BeautifulSoup(req.text, 'xml')  # Use 'xml' parser for XML documents
                # Print the key-value pairs
                for child in soup.find_all():
                    title = child.find("Title")
                    cve_notes = child.find("Notes")
                    cve = child.find("CVE")
                    description = child.find("Description")
                    if cve is not None:
                        cve_value = cve.text



                        # Check if the record with the same CVE value exists
                        if not DB_Class.record_exists(cve_value):
                            # Create a dictionary with the key-value pairs
                            data_dict = {
                                'Title': title.text if title else None,
                                'CVE': cve_value,
                                'Description': cve_notes.text,
                                "Month": cvrf_date
                            }
                            print(data_dict)
                            DB_Class.add_record(data_dict)
                            
                            for note in child.find_all('Note'):
                                note_data = {
                                    'CVE': cve_value,
                                    'Type': note.get('Type'),
                                    'Title': note.get('Title'),
                                    'Content': note.text
                                    }
                            DB_Class.add_note_record(note_data)

                            # Extract and add remediation information
                            for red in child.find_all('Remediations'):
                                red_data = {
                                    'CVE': cve_value,
                                    'Type': red.get('Type'),
                                    'Description': red.find("Description").text if red.find("Description") else None,
                                    'URL': red.find("URL").text if red.find("URL") else None,
                                    'KB': red.find("KB").text if red.find("KB") else None,
                                    'Supercedence': red.find("Supercedence").text if red.find("Supercedence") else None,
                                    'ProductID': red.find("ProductID").text if red.find("ProductID") else None,
                                    'RestartRequired': red.find("RestartRequired").text if red.find(
                                        "RestartRequired") else None,
                                    'SubType': red.find("SubType").text if red.find("SubType") else None
                                }
                                DB_Class.add_remediation_record(red_data)
                        else:
                            print(f"Record already exists for CVE: {cve_value}")

            else:
                print("Error: Empty response from the API")

        except Exception as e:
            print("Error querying CVRF:", e)
            return False

    def __del__(self):
        self.session.close()


class DatabaseClass:
    def __init__(self):
        self.db = 'cvrf_database.db'
        self.conn = sqlite3.connect(self.db)
        self.cur = self.conn.cursor()
        self.create_tables()  # Create the tables if they don't exist

    def get_connection(self):
        return sqlite3.connect(self.db)

    def create_tables(self):
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS Vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Title TEXT,
                CVE TEXT UNIQUE,
                Description TEXT,
                Note TEXT,
                FAQ TEXT, 
                Month TEXT
            )
        ''')
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS Products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ProductID INTEGER,
                VulnerabilityID INTEGER,
                FOREIGN KEY (VulnerabilityID) REFERENCES Vulnerabilities (id)
            )
        ''')
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS Threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Type TEXT,
                Description TEXT,
                ProductID INTEGER,
                VulnerabilityID INTEGER,
                FOREIGN KEY (VulnerabilityID) REFERENCES Vulnerabilities (id)
            )
        ''')

        self.cur.execute('''
              CREATE TABLE IF NOT EXISTS Remediations (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  CVE TEXT,
                  Type TEXT,
                  Description TEXT,
                  URL TEXT,
                  KB TEXT,
                  Supercedence TEXT,
                  ProductID INTEGER,
                  RestartRequired TEXT,
                  SubType TEXT,
                  FOREIGN KEY (CVE) REFERENCES Vulnerabilities (CVE)
              )
          ''')

        # Create a new Notes table
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS Notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                CVE TEXT,
                Type TEXT,
                Title TEXT,
                Content TEXT,
                FOREIGN KEY (CVE) REFERENCES Vulnerabilities (CVE)
            )
        ''')
        self.conn.commit()

    def add_remediation_record(self, data_dict):
        try:
            cve_value = data_dict.get('CVE')
            if cve_value:
                # Prepare the column names and values for the insert statement
                columns = ', '.join(data_dict.keys())
                placeholders = ', '.join(['?'] * len(data_dict))
                values = tuple(data_dict.values())

                # Create and execute the insert statement
                insert_sql = f"INSERT INTO Remediations ({columns}) VALUES ({placeholders})"
                self.cur.execute(insert_sql, values)

                # Commit the changes
                self.conn.commit()
                print(f"Remediation record added successfully for CVE: {cve_value}")
                return True
            else:
                print("CVE value not found in data_dict.")
                return False
        except sqlite3.Error as e:
            print(f"Error adding remediation record: {e}")
            return False

    def add_note_record(self, note_data):
        try:
            # Prepare the column names and values for the insert statement
            columns = ', '.join(note_data.keys())
            placeholders = ', '.join(['?'] * len(note_data))
            values = tuple(note_data.values())

            # Create and execute the insert statement
            insert_sql = f"INSERT INTO Notes ({columns}) VALUES ({placeholders})"
            self.cur.execute(insert_sql, values)

            # Commit the changes
            self.conn.commit()
            print("Note record added successfully")
            return True
        except sqlite3.Error as e:
            print(f"Error adding note record: {e}")
            return False
    
    def add_product_record(self, product_data):
        try:
            # Prepare the column names and values for the insert statement
            columns = ', '.join(product_data.keys())
            placeholders = ', '.join(['?'] * len(product_data))
            values = tuple(product_data.values())

            # Create and execute the insert statement
            insert_sql = f"INSERT INTO Products ({columns}) VALUES ({placeholders})"
            self.cur.execute(insert_sql, values)

            # Commit the changes
            self.conn.commit()
            print("Product record added successfully")
            return True
        except sqlite3.Error as e:
            print(f"Error adding product record: {e}")
            return False
    
    def add_threat_record(self, threat_data):
        try:
            # Prepare the column names and values for the insert statement
            columns = ', '.join(threat_data.keys())
            placeholders = ', '.join(['?'] * len(threat_data))
            values = tuple(threat_data.values())

            # Create and execute the insert statement
            insert_sql = f"INSERT INTO Threats ({columns}) VALUES ({placeholders})"
            self.cur.execute(insert_sql, values)

            # Commit the changes
            self.conn.commit()
            print("Threat record added successfully")
            return True
        except sqlite3.Error as e:
            print(f"Error adding threat record: {e}")
            return False
    


    def record_exists(self, cve_value):
        try:
            # Check if a record with the same CVE value already exists
            existing_record = self.cur.execute("SELECT * FROM Vulnerabilities WHERE CVE = ?", (cve_value,)).fetchone()
            if existing_record:
                return True
            else:
                return False
        except sqlite3.Error as e:
            print("Error checking if record exists:", e)
            return False

    def add_record(self, data_dict):
        try:
            cve_value = data_dict.get('CVE')
            if cve_value:
                # Check if a record with the same CVE already exists
                existing_record = self.cur.execute("SELECT * FROM Vulnerabilities WHERE CVE = ?",
                                                   (cve_value,)).fetchone()
                if existing_record:
                    print(f"Record already exists for CVE: {cve_value}")
                    return False

            # Prepare the column names and values for the insert statement
            columns = ', '.join(data_dict.keys())
            placeholders = ', '.join(['?'] * len(data_dict))
            values = tuple(data_dict.values())

            # Create and execute the insert statement
            insert_sql = f"INSERT INTO Vulnerabilities ({columns}) VALUES ({placeholders})"
            self.cur.execute(insert_sql, values)

            # Commit the changes
            self.conn.commit()
            print(f"Record added successfully for CVE: {cve_value}")
            return True
        except sqlite3.Error as e:
            print(f"Error adding record: {e}")
            return False