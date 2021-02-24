from time import sleep
import multiprocessing


def server():
    print("Shutting server down...")
	for process in multiprocessing.active_children():
		print("Shutting down process: ", process)
		process.terminate()
		process.join()


def process():
    print("kill process here!")
    sleep(60*60*24)
