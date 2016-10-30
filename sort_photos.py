#!/usr/bin/python

from PIL import Image
from PIL.ExifTags import TAGS
from datetime import datetime
import subprocess
from distutils.dir_util import mkpath
import os
import hashlib
import sqlite3
import filecmp

SOURCE_DIR = '/Data/Media/unsorted/Photo'
DEST_DIR = '/Data/Media/Photos'
CATALOGUE_FILE = '%s/.sort_photo_catalogue.sqlite' % DEST_DIR

file_hashes = []

def get_exif(fn):
    ret = {}
    i = Image.open(fn)
    info = i._getexif()
    for tag, value in info.items():
        decoded = TAGS.get(tag, tag)
        ret[decoded] = value
    return ret

def checksum(fname, checksum_type='md5'):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Temporary hack to list files - seemed initially to be quicker than
# walking the directories
files = subprocess.check_output(['find', SOURCE_DIR,
                                 '-type', 'f',
                                 '-regex', '.*\.\(JPG\|GIF\|JPEG\|PNG\|jpg\|gif\|png\|jpeg\)'])

create_schema = not os.path.isfile(CATALOGUE_FILE)
conn = sqlite3.connect(CATALOGUE_FILE)
c = conn.cursor()
if create_schema:
    print 'Creating table'
    c.execute('''CREATE TABLE photo(source_path text, md5sum text, dest_path text, year text,
                                     month text, status text)''')
    conn.commit()

for file_path in files.split("\n"):
    conn.commit()
    print 'Processing %s' % file_path
    try:
        # Determine if file has already been processed
        res = c.execute('''SELECT count(*) FROM photo WHERE source_path=?''', (file_path,))
        if res.fetchone()[0]:
            print 'Found file with same source path'
            continue

        md5sum = checksum(file_path)
        # Check for duplicate photos
        res = c.execute('''SELECT source_path FROM photo WHERE md5sum=?''', (md5sum,)).fetchall()
        if len(res):
            found_dupe = False
            for dupe_source_file in res:
                print 'Found dupe MD5'
                if filecmp.cmp(file_path, dupe_source_file[0]):
                    print 'Found dupe photo'
                    found_dupe = True
            if found_dupe:
                continue

        try:
            exif_data = get_exif(file_path)
        except:
            c.execute('''INSERT INTO photo(source_path, md5sum, status) VALUES(?, ?, ?)''',
                      (file_path, md5sum, 0))
            print 'Failed to get exif'
            continue

        date_time = None
        date = None
        if 'DateTimeOriginal' in exif_data:
            date = exif_data['DateTimeOriginal']
        elif 'DateTime' in exif_data:
            date = exif_data['DateTime']
        elif 'DateTimeDigitized' in exif_data:
            date = exif_data['DateTimeDigitized']

        if 'ExifImageHeight' in exif_data and int(exif_data['ExifImageHeight']) < 65:
            c.execute('''INSERT INTO photo(source_path, md5sum, status) VALUES(?, ?, ?)''',
                      (file_path, md5sum, 0))
            print 'too small'
            continue
        if 'ExifImageWidth' in exif_data and str(exif_data['ExifImageWidth']) < 65:
            c.execute('''INSERT INTO photo(source_path, md5sum, status) VALUES(?, ?, ?)''',
                      (file_path, md5sum, 0))
            print 'too small'
            continue

        try:
            if not date_time:
                date_time = datetime.strptime(str(date), '%Y:%m:%d %H:%M:%S')
        except:
            date_time = None

        if date_time is None:
            dt = os.path.getmtime(file_path)
            date_time = datetime.fromtimestamp(dt)

        dest_dir = '%s/%s/%s' % (DEST_DIR, date_time.year, date_time.month)

        file_name = file_path.split('/')[-1]
        dest_filename = file_name

        filename_itx = 1
        while True:
            dest_path = '%s/%s' % (dest_dir, dest_filename)
            if not os.path.exists(dest_path):
                break
            filename_itx += 1
            dest_filename = '%s-%s.%s' % ('.'.join(file_name.split('.')[0:-1]),
                                          filename_itx,
                                          file_name.split('.')[-1])

        if not os.path.exists(dest_dir):
            mkpath(dest_dir)

        # determine free name
        os.symlink(file_path, dest_path)
        c.execute('''INSERT INTO photo(source_path, md5sum, dest_path, year, month, status)
                     VALUES(?, ?, ?, ?, ?, ?)''',
                  (file_path, md5sum, dest_path, date_time.year, date_time.month, 0))
        print 'finished processing'
    except Exception, e:
        print 'Found exception: %s' % str(e)
        pass
conn.commit()
