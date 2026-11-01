from aws_s3_manager import upload_file_to_s3

result = upload_file_to_s3(
    "aws-test.txt"
)

if result:
    print("DataShadow AWS S3 integration test PASSED")
else:
    print("DataShadow AWS S3 integration test FAILED")