from ffmpeg_streaming import Formats
import ffmpeg_streaming
import time
from threading import current_thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


class Transcode:

    @staticmethod
    def hls(key, value):
        start_time = time.perf_counter()
        hls_video = ffmpeg_streaming.input(value)
        hls = hls_video.hls(Formats.h264(), hls_time=5.5, start_number=0)
        hls.auto_generate_representations([1080, 720, 480, 360, 240, 144])
        hls.output(f"{Path.cwd()}/output/hls/{key}/hls.m3u8")
        print("Executing thread name :", current_thread().getName())
        print(f"--- HLS finished in: {round(time.perf_counter() - start_time, 2)} seconds ---")

    @staticmethod
    def dash(key, value):
        start_time = time.perf_counter()
        dash_video = ffmpeg_streaming.input(value)
        dash = dash_video.dash(Formats.h264())
        dash.auto_generate_representations([1080, 720, 480, 360, 240, 144])
        dash.output(f"{Path.cwd()}/output/dash/{key}/dash.mpd")
        print("Executing thread name:", current_thread().getName())
        print(
            f"--- DASH finished in: {round(time.perf_counter() - start_time, 2)} seconds ---")


def main(videos):
    transcode = Transcode()
    with ThreadPoolExecutor(max_workers=len(videos)) as executor:
        hls_transcode = {executor.submit(transcode.hls, k, v): (k, v) for k, v in videos.items()}
        for hls in as_completed(hls_transcode):
            k, v = hls_transcode[hls]
            print('k: ', k, 'v: ', v)

        dash_transcode = {executor.submit(transcode.dash, k, v): (k, v) for k, v in videos.items()}
        for dash in as_completed(dash_transcode):
            k, v = dash_transcode[dash]
            print('k: ', k, 'v: ', v)


if __name__ == "__main__":
    video_lists = {
        0: '30_sec_1080p_wc.mp4',
        1: '30_sec_1080p_wc.mp4',
    }
    main(video_lists)
