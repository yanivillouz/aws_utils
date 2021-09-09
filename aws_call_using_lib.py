import boto3
import requests # pip install requests
from aws_requests_auth.aws_auth import AWSRequestsAuth

service = 'execute-api'
host = 'XXXXXXXXXX.execute-api.eu-west-1.amazonaws.com'
region = 'eu-west-1'
endpoint = 'https://XXXXXXXXXX.execute-api.eu-west-1.amazonaws.com/YYYYYYYYYY'

def main():
    # Read AWS access key from env. variables or configuration file. Best practice is NOT
    # to embed credentials in code.
    session = boto3.Session()
    credentials = session.get_credentials()
    auth = AWSRequestsAuth(aws_access_key=credentials.access_key,
                        aws_secret_access_key=credentials.secret_key,
                        aws_token=credentials.token,
                        aws_host=host,
                        aws_region=region,
                        aws_service=service)

    response = requests.post(url=endpoint, auth=auth, json=payload)
    print (response.text)

if __name__ == "__main__":
	main()
