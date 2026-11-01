import boto3

AWS_REGION = "us-east-1"

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:478092416663:DataShadowSecurityAlerts"

sns = boto3.client(
    "sns",
    region_name=AWS_REGION
)


def send_security_alert(
    filename,
    risk_level,
    risk_score,
    owner_email,
    reason
):
    try:

        subject = f"DataShadow Security Alert - {risk_level}"

        message = f"""
DataShadow Security Alert

A security risk has been detected.

File: {filename}
Risk Level: {risk_level}
Risk Score: {risk_score}
Owner: {owner_email}

Reason:
{reason}

Please review this file in the DataShadow Security Dashboard.
"""

        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

        print("====================================")
        print("SNS SECURITY ALERT SENT")
        print("File:", filename)
        print("Risk Level:", risk_level)
        print("Risk Score:", risk_score)
        print("Message ID:", response["MessageId"])
        print("====================================")

        return True

    except Exception as e:

        print("====================================")
        print("SNS SECURITY ALERT ERROR")
        print(e)
        print("====================================")

        return False