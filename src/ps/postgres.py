from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.types import PickleType, Text

import os
import json

app = Flask(__name__)
app.config.from_object((os.environ['SP_APP_SETTINGS']))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class CVES(db.Model):
    __tablename__ = 'cves'

    _id = db.Column(db.Sequence, primary_key=True)
    # -> cve['CVE_data_meta']['ID']
    id = db.Column(db.String)                           # CVE_data_meta -> ID
    # -> cve['CVE_data_meta']['ASSIGNER']
    assigner = db.Column(db.String)                     # CVE_data_meta -> ASSIGNER
    # -> cve['data_type']
    data_type = db.Column(db.String)                    # data_type like "CVE"
    # -> cve['data_format']
    data_format = db.Column(db.String)                  # data_format like "MITRE"
    # -> cve['data_version']
    data_version = db.Column(db.String)                 # data_version like "4.0"
    # -> cve['affects']['vendor']['vendor_data'][0]
    vendor_data = db.Column(db.String)                  # [Link] to Vendors TABLE record
    # -> cve['problemtype']['problemtype_data'][0]['description'][0]['value']
    cwe = db.Column(db.String)                          # CWE Value
    cwe_link = db.Column(db.String)                     # Link to CWE TABLE
    cpe22 = db.Column(db.ARRAY)                         # cpe22Uri
    cpe23 = db.Column(db.ARRAY)                         # cpe23Uri
    base_metric_v3 = db.Column(JSON)                    # impact
    base_metric_v2 = db.Column(JSON)                    # impact
    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)
    references = db.Column(db.ARRAY)                    # urls
    description = db.Column(db.String)                  # Description or summary

    def __init__(self):
        pass

    def __repr__(self):
        return '<id: {}, CVE: {}>'.format(self._id, self.id)


class CWE(db.Model):
    __tablename__ = 'cwe'

    _id = db.Column(db.Sequence, primary_key=True)
    id = db.Column(db.String)

    def __init__(self):
        pass

    def __repr__(self):
        return '<id: {}, CWE: {}>'.format(self._id, self.id)

class Vendors(db.Model):
    __tablename__ = 'vendors'

    _id = db.Column(db.Sequence, primary_key=True)
    vendor_name = db.Column(db.String)                  # Vendor name like microsoft, google,...
    products = db.Column(db.ARRAY)                      # Product [links] to Products TABLE records


class Products(db.Model):
    __tablename__ = 'products'

    _id = db.Column(db.Sequence, primary_key=True)      # Record ID
    product_name = db.Column(db.String, index=True)     # Product_name like windows_10 (index)
    version_value = db.Column(db.ARRAY)                 # Version_value like -, 1511, 1607, 1703, ...


def populate_cve():
    pass


def update_cve():
    pass

@app.route('/')
def route_index():
    return 'Index'

@app.route('/update_cve')
def route_update_cve():
    return update_cve()

@app.route('/populate_cve')
def route_populate_cve():
    return populate_cve()


if __name__ == '__main__':
    app.run(
        host='localhost',
        port=3000,
        debug=True
    )