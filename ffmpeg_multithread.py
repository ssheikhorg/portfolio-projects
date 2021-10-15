from ffmpeg_streaming import Formats
import ffmpeg_streaming, logging, time
from threading import *
from concurrent.futures import ThreadPoolExecutor


class Transcode:

    def hls(self, video, thread):
        start_time = time.perf_counter()
        logging.basicConfig(level=logging.DEBUG)
        hls_video = ffmpeg_streaming.input(video)
        hls = hls_video.hls(Formats.h264(), hls_time=5.5, start_number=0)
        hls.auto_generate_representations([1080, 720, 480, 360, 240, 144])
        hls.output(f"/Users/ss/Desktop/djax/output/hls/{thread}/hls.m3u8")
        print("Executing thread name :", current_thread().getName())
        print(f"--- HLS finished in: {round(time.perf_counter() - start_time, 2)} seconds ---")

    def dash(self, video, thread):
        start_time = time.perf_counter()
        dash_video = ffmpeg_streaming.input(video)
        dash = dash_video.dash(Formats.h264())
        dash.auto_generate_representations([1080, 720, 480, 360, 240, 144])
        dash.output(f"/Users/ss/Desktop/djax/output/dash/{thread}/dash.mpd")
        print("Executing thread name:", current_thread().getName())
        print(f"--- DASH finished in: {round(time.perf_counter() - start_time, 2)} seconds ---")


def main():
    transcode = Transcode()
    video_list = ['30_sec_1080p_wc.mp4', '2nd_video.mp4']
    with ThreadPoolExecutor(max_workers=4) as executor:
        for list in video_list:
            executor.submit(transcode.hls, list, video_list.index)
        # executor.submit(transcode.hls, playlist[1], 'hls_2')
        # executor.submit(transcode.hls, '30_sec_1080p_wc.mp4', 'hls_2')
        # executor.submit(transcode.dash, '30_sec_1080p_wc.mp4', 'dash_1')
        # executor.submit(transcode.dash, '30_sec_1080p_wc.mp4', 'dash_2')


if __name__ == "__main__":
    main()

print("Master Thread: ", current_thread().getName())
