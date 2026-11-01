import boto3
import os

AWS_REGION = "us-east-1"
BUCKET_NAME = "myprojectbucket250926"

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION
)


def upload_file_to_s3(file_path, object_name=None):

    try:

        if object_name is None:
            object_name = os.path.basename(file_path)

        s3.upload_file(
            file_path,
            BUCKET_NAME,
            object_name
        )

        print("====================================")
        print("AWS S3 UPLOAD SUCCESSFUL")
        print("Bucket:", BUCKET_NAME)
        print("File:", object_name)
        print("====================================")

        return True

    except Exception as e:

        print("====================================")
        print("AWS S3 UPLOAD ERROR")
        print(e)
        print("====================================")

        return False