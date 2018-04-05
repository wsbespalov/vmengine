import json
import hashlib

file_en = '/Users/admin/Projects/vmengine/src/ps/locale-en.json'
file_ru = '/Users/admin/Projects/vmengine/src/ps/locale-ru.json'

with open(file_en, 'r') as f_file_en:
    s_file_en = json.load(f_file_en)

with open(file_ru, 'r') as f_file_ru:
    s_file_ru = json.load(f_file_ru)


md5_object_en = hashlib.md5(json.dumps(s_file_en))
print('MD5 Hash for file_en: {}'.format(md5_object_en.hexdigest()))

md5_object_ru = hashlib.md5(json.dumps(s_file_ru))
print('MD5 Hash for file_ru: {}'.format(md5_object_ru.hexdigest()))

hash_object_en = hashlib.sha1(json.dumps(s_file_en))
print('SHA1 Hash for file_en: {}'.format(hash_object_en.hexdigest()))

hash_object_ru = hashlib.sha1(json.dumps(s_file_ru))
print('SHA1 Hash for file_ru: {}'.format(hash_object_ru.hexdigest()))

hash256_object_en = hashlib.sha256(json.dumps(s_file_en))
print('SHA256 Hash for file_en: {}'.format(hash256_object_en.hexdigest()))

hash256_object_ru = hashlib.sha256(json.dumps(s_file_ru))
print('SHA256 Hash for file_ru: {}'.format(hash256_object_ru.hexdigest()))