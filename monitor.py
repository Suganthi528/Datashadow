import os
import time
import getpass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database import get_db_connection


UPLOAD_FOLDER = os.path.abspath("uploads")


class FileMonitorHandler(FileSystemEventHandler):

    def save_activity(self, activity_type, description, filename=""):

        try:

            system_user = getpass.getuser()

            conn = get_db_connection()
            cursor = conn.cursor()

            sql = """
            INSERT INTO activity_logs
            (username, user_email, activity_type, description, filename)
            VALUES (%s, %s, %s, %s, %s)
            """

            cursor.execute(
                sql,
                (
                    system_user,
                    "system",
                    activity_type,
                    description,
                    filename
                )
            )

            conn.commit()

            cursor.close()
            conn.close()

        except Exception as e:

            print("Database logging error:", e)

    def on_created(self, event):

        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        print("\n================================")
        print("NEW FILE DETECTED")
        print("================================")
        print("Filename :", filename)
        print("Path     :", event.src_path)
        print("Activity : FILE CREATED")
        print("Time     :", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("================================")

        self.save_activity(
            "FILE_CREATED",
            "New file detected in uploads folder",
            filename
        )

    def on_modified(self, event):

        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        print("\n================================")
        print("FILE MODIFIED")
        print("================================")
        print("Filename :", filename)
        print("Path     :", event.src_path)
        print("Activity : FILE MODIFIED")
        print("Time     :", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("================================")

        self.save_activity(
            "FILE_MODIFIED",
            "File was modified",
            filename
        )

    def on_deleted(self, event):

        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        print("\n================================")
        print("FILE DELETED")
        print("================================")
        print("Filename :", filename)
        print("Path     :", event.src_path)
        print("Activity : FILE DELETED")
        print("Time     :", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("================================")

        self.save_activity(
            "FILE_DELETED",
            "File was deleted",
            filename
        )

    def on_moved(self, event):

        if event.is_directory:
            return

        old_filename = os.path.basename(event.src_path)
        new_filename = os.path.basename(event.dest_path)

        print("\n================================")
        print("FILE RENAMED / MOVED")
        print("================================")
        print("Old Name :", old_filename)
        print("New Name :", new_filename)
        print("Activity : FILE MOVED")
        print("Time     :", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("================================")

        self.save_activity(
            "FILE_MOVED",
            f"File moved/renamed from {old_filename} to {new_filename}",
            new_filename
        )


if __name__ == "__main__":

    if not os.path.exists(UPLOAD_FOLDER):

        os.makedirs(UPLOAD_FOLDER)

    event_handler = FileMonitorHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        UPLOAD_FOLDER,
        recursive=True
    )

    observer.start()

    print("==========================================")
    print("       DataShadow Automatic Monitoring")
    print("==========================================")
    print("Monitoring folder:")
    print(UPLOAD_FOLDER)
    print("------------------------------------------")
    print("Monitoring:")
    print("1. File creation")
    print("2. File modification")
    print("3. File deletion")
    print("4. File movement / rename")
    print("------------------------------------------")
    print("Waiting for file activity...")
    print("Press CTRL+C to stop.")
    print("==========================================")

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print("\nStopping monitor...")

        observer.stop()

    observer.join()

    print("Monitoring stopped.")