

# New structure for JSON CVE source

CVE_data_numberOfCVEs = 959 -> number of items

{
  "CVE_data_type" : "CVE",
  "CVE_data_format" : "MITRE",
  "CVE_data_version" : "4.0",
  "CVE_data_numberOfCVEs" : "959",
  "CVE_data_timestamp" : "2018-03-28T14:00Z",
  "CVE_Items" : [ {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "CVE-2001-1594",
        "ASSIGNER" : "cve@mitre.org"
      },
      "affects" : {
        "vendor" : {
          "vendor_data" : [ {
            "vendor_name" : "gehealthcare",
            "product" : {
              "product_data" : [ {
                "product_name" : "entegra_p&r",
                "version" : {
                  "version_data" : [ {
                    "version_value" : "*"
                  } ]
                }
              } ]
            }
          } ]
        }
      },
      "problemtype" : {
        "problemtype_data" : [ {
          "description" : [ {
            "lang" : "en",
            "value" : "CWE-255"
          } ]
        } ]
      },
      "references" : {
        "reference_data" : [ {
          "url" : "http://apps.gehealthcare.com/servlet/ClientServlet/2263784.pdf?DOCCLASS=A&REQ=RAC&DIRECTION=2263784-100&FILENAME=2263784.pdf&FILEREV=5&DOCREV_ORG=5&SUBMIT=+ACCEPT+"
        }, {
          "url" : "http://www.forbes.com/sites/thomasbrewster/2015/07/10/vulnerable-breasts/"
        }, {
          "url" : "https://ics-cert.us-cert.gov/advisories/ICSMA-18-037-02"
        }, {
          "url" : "https://twitter.com/digitalbond/status/619250429751222277"
        } ]
      },
      "description" : {
        "description_data" : [ {
          "lang" : "en",
          "value" : "GE Healthcare eNTEGRA P&R has a password of (1) entegra for the entegra user, (2) passme for the super user of the Polestar/Polestar-i Starlink 4 upgrade, (3) 0 for the entegra user of the Codonics printer FTP service, (4) eNTEGRA for the eNTEGRA P&R user account, (5) insite for the WinVNC Login, and possibly other accounts, which has unspecified impact and attack vectors.  NOTE: it is not clear whether this password is default, hardcoded, or dependent on another system or product that requires a fixed value."
        } ]
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [ {
        "operator" : "OR",
        "cpe" : [ {
          "vulnerable" : true,
          "cpe22Uri" : "cpe:/a:gehealthcare:entegra_p%26r",
          "cpe23Uri" : "cpe:2.3:a:gehealthcare:entegra_p\\&r:*:*:*:*:*:*:*:*"
        } ]
      } ]
    },
    "impact" : {
      "baseMetricV2" : {
        "cvssV2" : {
          "version" : "2.0",
          "vectorString" : "(AV:N/AC:L/Au:N/C:C/I:C/A:C)",
          "accessVector" : "NETWORK",
          "accessComplexity" : "LOW",
          "authentication" : "NONE",
          "confidentialityImpact" : "COMPLETE",
          "integrityImpact" : "COMPLETE",
          "availabilityImpact" : "COMPLETE",
          "baseScore" : 10.0
        },
        "severity" : "HIGH",
        "exploitabilityScore" : 10.0,
        "impactScore" : 10.0,
        "obtainAllPrivilege" : false,
        "obtainUserPrivilege" : false,
        "obtainOtherPrivilege" : false,
        "userInteractionRequired" : false
      }
    },
    "publishedDate" : "2015-08-04T14:59Z",
    "lastModifiedDate" : "2018-03-28T01:29Z"
  },


#

from datetime import datetime

from ming import Session
from ming import create_datastore
from ming import Document
from ming import Field
from ming import schema as S
from ming import collection


DATASTORE = 'VulnerabilityManagement'

bind = create_datastore('tutorial')
session = Session(bind)

# class Users(Document):
#
#     class __mongometa__:
#         session = session
#         name = 'users'
#
#     _id = Field(S.ObjectId)
#     username = Field(str)
#     age = Field(int)

USER = collection(
    'users',
    session,
    Field('_id', S.ObjectId()),
    Field('username', S.String(if_missing='')),
    Field('age', S.Int(if_missing=0))
)

def create_user(user_info):
    # type: (dict) -> None
    if isinstance(user_info, dict):
        f = session.db.USER.find({"username": "Petya"})
        print(f)

# def create_user(user_info):
#     # type: (dict) -> None
#     if isinstance(user_info, dict):
#         user = Users(user_info).m.save()
#         return Users.m.get(username=user_info['username'])

create_user(dict(username='Petya', age=29))


class CVES(Document):
    class mongometa:
        session=session
        name='cves'
    _id = Field(S.ObjectId())
    id = Field(S.String(if_missing=''))
    References = Field(S.Array(field_type=str))
    VulnerableConfiguration = Field(S.Array(field_type=str))
    VulnerableConfigurationCPE22 = Field(S.Array(field_type=str))
    Published = Field(S.DateTime(if_missing=datetime.utcnow()))
    Modified = Field(S.DateTime(if_missing=datetime.utcnow()))
    CVSS = Field(S.Int(if_missing=0))
    Access = Field(S.Object(dict(
        vector=S.String(if_missing=''),
        complexity=S.String(if_missing=''),
        authentication=S.String(if_missing='')))),
    Impact = Field(S.Object(dict(
        confidentiality=S.String(if_missing=''),
        integrity=S.String(if_missing=''),
        availability=S.String(if_missing='')))),
    CVSSTime = Field(S.DateTime(if_missing=datetime.utcnow()))
    CWE = Field(S.String(if_missing=''))
    Summary = Field(S.String(if_missing=''))


CVES2 = collection(
    'cves',
    session,
    Field('_id',S.ObjectId()),
    Field('id', S.String(if_missing='')),
    Field('references', S.Array(field_type=str)),
    Field('vulnerable_configuration', S.Array(field_type=str)),
    Field('vulnerable_configuration_cpe_2_2', S.Array(field_type=str)),
    Field('Published', S.DateTime(if_missing=datetime.utcnow())),
    Field('Modified', S.DateTime(if_missing=datetime.utcnow())),
    Field('cvss', S.Int(if_missing=0)),
    Field('access', S.Object(dict(
        vector=S.String(if_missing=''),
        complexity=S.String(if_missing=''),
        authentication=S.String(if_missing='')))),
    Field('impact', S.Object(dict(
        confidentiality=S.String(if_missing=''),
        integrity=S.String(if_missing=''),
        availability=S.String(if_missing='')))),
    Field('cvss-time', S.DateTime(if_missing=datetime.utcnow())),
    Field('cwe', S.String(if_missing='')),
    Field('summary', S.String(if_missing=''))
)

VULNERS = collection(
    'vulners',
    session,
    Field('_id', S.ObjectId()),
    Field('Component', S.String(if_missing='')),
    Field('Version', S.String(if_missing='0')),
    Field('Created', S.DateTime(if_missing=datetime.utcnow())),
    Field('Status', S.String(if_missing='Open')),
    Field('CVETitle', S.String(if_missing='')),
    Field('Author', S.String(if_missing='VMAutoSearch')),
    Field('Published', S.DateTime(if_missing=datetime.utcnow())),
    Field('Modified', S.DateTime(if_missing=datetime.utcnow())),
    Field('Summary', S.String(if_missing='')),
    Field('References', S.Array(field_type=str)),
    Field('CVSSScore', S.String(if_missing='0')),
    Field('Access', S.Object(dict(
        Vector=S.String(if_missing=''),
        Complexity=S.String(if_missing=''),
        Authentication=S.String(if_missing='')))),
    Field('Impact', S.Object(dict(
        Confidentiality=S.String(if_missing=''),
        Integrity=S.String(if_missing=''),
        Availability=S.String(if_missing=''),
        ))),
    Field('VulnerabilityType', S.String(if_missing='')),
    Field('ProductsAffectedBy', S.Array(field_type=dict(
        ProductType=S.String(if_missing=''),
        Vendor=S.String(if_missing=''),
        Product=S.String(if_missing=''),
        Version=S.String(if_missing=''),
        Update=S.String(if_missing=''),
        Edition=S.String(if_missing=''),
        Language=S.String(if_missing=''),
        Details=S.String(if_missing='')
    ))),
    Field('VulnerableVersions', S.String(if_missing='')),
    Field('PatchedVersions', S.String(if_missing='')),
    Field('Recomendations', S.String(if_missing='')),
    # Links for dabtabases
    Field('cpe', S.Array(field_type=str)),
    Field('cves', S.Array(field_type=str)),
    Field('cwe', S.Array(field_type=str)),
    Field('capec', S.Array(field_type=str)),
    Field('cpeother', S.Array(field_type=str)),
    Field('via4', S.Array(field_type=str)),
    Field('npm', S.Array(field_type=str)),
    Field('ms', S.Array(field_type=str)),
    Field('exploitdb', S.Array(field_type=str)),
    Field('d2sec', S.Array(field_type=str))
)