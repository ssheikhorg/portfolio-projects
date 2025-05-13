from ffmpeg_streaming import Formats
import ffmpeg_streaming
import time
from threading import current_thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def hls_func(key, value):
    start_time = time.perf_counter()
    hls_video = ffmpeg_streaming.input(value)
    hls = hls_video.hls(Formats.h264(), hls_time=5.5, start_number=0)
    hls.auto_generate_representations([1080, 720, 480, 360, 240, 144])
    hls.output(f"{Path.cwd()}/output/hls/{key}/hls.m3u8")
    print("Executing thread name :", current_thread().getName())
    print(
        f"--- HLS finished in: {round(time.perf_counter() - start_time, 2)} seconds ---"
    )


def dash_func(key, value):
    start_time = time.perf_counter()
    dash_video = ffmpeg_streaming.input(value)
    dash = dash_video.dash(Formats.h264())
    dash.auto_generate_representations([1080, 720, 480, 360, 240, 144])
    dash.output(f"{Path.cwd()}/output/dash/{key}/dash.mpd")
    print("Executing thread name:", current_thread().getName())
    print(
        f"--- DASH finished in: {round(time.perf_counter() - start_time, 2)} seconds ---"
    )


def main(videos):
    # Multi Threading
    with ThreadPoolExecutor(max_workers=len(videos)) as executor:
        hls_transcode = {
            executor.submit(hls_func, k, v): (k, v) for k, v in videos.items()
        }
        for hls in as_completed(hls_transcode):
            k, v = hls_transcode[hls]
            print("result: ", hls.result())

        dash_transcode = {
            executor.submit(dash_func, k, v): (k, v) for k, v in videos.items()
        }
        for dash in as_completed(dash_transcode):
            k, v = dash_transcode[dash]
            # print('k: ', k, 'v: ', v)


video_lists = {
    "one": "30_sec_1080p_wc.mp4",
    "two": "30_sec_1080p_wc.mp4",
    # 'three': '30_sec_1080p_wc.mp4',
    # 'four': '30_sec_1080p_wc.mp4',
    # 'five': '30_sec_1080p_wc.mp4',
}

if __name__ == "__main__":
    main(video_lists)
