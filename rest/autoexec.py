#!/usr/bin/env python3
# Copyright (c), MusicInxite, Inc. All rights reserved.
#
# Developed By Saim Ehsan
# http://saimehsan.com

import os
import json
import copy
import sqlite3

from time import sleep
from datetime import date, time, datetime, timedelta
import xbmc

CURRENT_USER = str(os.environ.get('USER'))
CONFIG_FILE = '/home/' + CURRENT_USER + '/.kodi/addons/service.autoexec/config.json'


def read_json(str_json):
    '''
    Load json from string

    :return: loaded json or empty list if invalid string
    :rtype: list
    '''
    try:
        return json.load(str_json)
    except ValueError as e:
        return []


def db_connect():
    '''
    Connection to the database

    :return: connection and cursor if connected successfully
    :rtype: tuple
    '''
    db_name = 'MusicInxite.db'

    try:
        # Connect to DB and create a cursor
        conn = sqlite3.connect('/home/' + CURRENT_USER + '/.kodi/userdata/Database/' + db_name)
        cursor = conn.cursor()

        print(sqlite3.version)

        cursor.execute('''CREATE TABLE IF NOT EXISTS lastplayed(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        artist TEXT,
                        albumlabel TEXT,
                        mediapath TEXT,
                        played_at INTEGER
                       );''')

        return conn, cursor
    except sqlite3.Error as error:
        xbmc.log(error, xbmc.LOGINFO)
        return None, None


def track_remaining_time():
    '''
    Get current track remaining time

    :return: time it takes to complete the current music track
    :rtype: float
    '''
    playlist_info = json.loads(xbmc.executeJSONRPC(
        '{"jsonrpc":"2.0","method":"Player.GetProperties","params":[0,["time", "totaltime"]],"id":12}'))

    cur_time = playlist_info['result']['time']
    total_time = playlist_info['result']['totaltime']

    xbmc.log(
        '[MusicInxite][autoexec] Current Time = ' + json.dumps(cur_time) + ' Total Time = ' + json.dumps(total_time),
        xbmc.LOGINFO)

    time_secs = (cur_time['hours'] * 60) * 60 + cur_time['minutes'] * 60 + cur_time['seconds'] + cur_time[
        'milliseconds'] / 1000
    totaltime_secs = (total_time['hours'] * 60) * 60 + total_time['minutes'] * 60 + total_time['seconds'] + total_time[
        'milliseconds'] / 1000
    time_diff = totaltime_secs - time_secs

    xbmc.log('[MusicInxite][autoexec] time_secs = ' + str(time_secs) + ' totaltime_secs = ' + str(
        totaltime_secs) + ' time_diff = ' + str(time_diff), xbmc.LOGINFO)
    xbmc.log('[MusicInxite][autoexec] Waiting for ' + str(time_diff) + ' seconds before switching playlist.',
             xbmc.LOGINFO)

    return time_diff


PREV_MEDIAPATH = PREV_ALBUM = PREV_ARTIST = None


def set_lastplayed(con, cur):
    '''
    Store last played track info in the sqlite database.

    :param Connection con: database connection
    :param Cursor cur: database connection cursor

    :return: None
    :rtype: void
    '''
    global PREV_MEDIAPATH, PREV_ALBUM

    playlist_info = json.loads(xbmc.executeJSONRPC(
        '{"jsonrpc":"2.0","method":"Player.GetItem","params":[0,["artist", "albumlabel", "mediapath"]],"id":12}'))
    mediapath = playlist_info['result']['item'].get('mediapath', None)
    albumlabel = playlist_info['result']['item'].get('label', None)
    artist = playlist_info['result']['item'].get('artist', [None])

    if len(artist):
        artist = artist[0]

    if PREV_MEDIAPATH != mediapath:
        if PREV_ALBUM != albumlabel and albumlabel and artist:
            played_at = int(datetime.timestamp(datetime.now()))

            if mediapath:
                cur.execute('''INSERT INTO lastplayed (artist, albumlabel, mediapath, played_at) VALUES (?, ?, ?, ?)''',
                            (artist, albumlabel, mediapath, played_at))

                con.commit()

                PREV_MEDIAPATH = copy.copy(mediapath)
                PREV_ALBUM = copy.copy(albumlabel)


c_conn, c_cursor = db_connect()

if not c_cursor:
    xbmc.log('[MusicInxite][autoexec] Unable to connect to sqlite database', xbmc.LOGINFO)

prev_schedule = -1

while True:
    if os.path.isfile(CONFIG_FILE):
        schedules = []

        for data in read_json(open(CONFIG_FILE, encoding='UTF-8')):
            schedules.append(
                {
                    'time': datetime.combine(date.today(), time(data['time']['h'], data['time']['m'])),
                    'duration': timedelta(hours=data['duration']['h'], minutes=data['duration']['m']),
                    'weekday': data['weekday'],
                    'volume': 90,
                    'command': '[{"jsonrpc":"2.0","method":"Playlist.Clear","params":[0],"id":11},{"jsonrpc":"2.0","method":"Playlist.Insert","params":[0,0,{"directory":"/home/' + CURRENT_USER + '/.kodi/userdata/playlists/music/' +
                               data[
                                   'playlist'] + '/"}],"id":10},{"jsonrpc":"2.0","method":"Player.Open","params":{"item":{"position":0,"playlistid":0},"options":{}},"id":16011}]'
                }
            )

        for x, schedule in enumerate(schedules):
            if prev_schedule != x:
                timestamp = datetime.now()

                set_lastplayed(c_conn, c_cursor)

                if ('command' in schedule and schedule['command'] is not None and \
                        ('weekday' not in schedule or \
                         schedule['weekday'] is None or \
                         len(schedule['weekday']) == 0 or \
                         timestamp.weekday() in schedule['weekday']) and \
                        timestamp >= schedule['time'] and \
                        timestamp < schedule['time'] + schedule['duration']):
                    xbmc.log('[MusicInxite][autoexec] Playlist = ' + str(x), xbmc.LOGINFO)

                    if xbmc.Player().isPlaying():
                        sleep(track_remaining_time())

                    try:
                        xbmc.executeJSONRPC(schedule['command'])
                        xbmc.executebuiltin('SetVolume(' + str(schedule['volume']) + ')')
                        xbmc.executebuiltin('PlayerControl(RandomOn)')
                        xbmc.executebuiltin('PlayerControl(RepeatAll)')
                        prev_schedule = x
                    except Exception as e:
                        xbmc.log('[MusicInxite][autoexec] Error: ' + str(e), xbmc.LOGINFO)
                        pass

                    sleep(30)
            else:
                sleep(1)
    else:
        sleep(5)
