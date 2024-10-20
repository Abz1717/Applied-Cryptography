import boto3
import hashlib
import random
from datetime import datetime, time

# Initialize the Boto3 Route 53 client
route53 = boto3.client('route53')

# Function to compute SHA-256 hash of the answer
def compute_hash(answer):
    return hashlib.sha256(answer.encode()).hexdigest()

# Function to generate a random arithmetic CAPTCHA
def generate_captcha():
    num1 = random.randint(1, 20)  # Random number between 1 and 20
    num2 = random.randint(1, 20)  # Random number between 1 and 20
    operator = random.choice(['+', '-'])  # Randomly choose between + and -
    
    if operator == '+':
        question = f"What is {num1} + {num2}?"
        answer = str(num1 + num2)  # Calculate the answer
    else:
        question = f"What is {num1} - {num2}?"
        answer = str(num1 - num2)  # Calculate the answer
    
    return question, answer

# Update the DNS TXT record in Route 53
def update_dns_txt_record(value):
    print(f"Updating DNS TXT record to: {value}")

    response = route53.change_resource_record_sets(
        HostedZoneId='Z1018078137EWKWPFEBZ5',
        ChangeBatch={
            'Comment': 'Update TXT DNS record for CAPTCHA',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': 'api.authservice.co.uk.',
                        'Type': 'TXT',
                        'TTL': 300,
                        'ResourceRecords': [{'Value': f'"{value}"'}]  # Include the double quotes for TXT record
                    }
                }
            ]
        }
    )
    
    print(f"Response from Route 53: {response}")
    return response

# Lambda handler to process incoming requests
def lambda_handler(event, context):
    # Simulate retrieving the Transaction ID from a DNS query
    # For example purposes, let's assume it's provided in the event.
    transaction_id = event.get('transaction_id', 0x1234)
    
    # Decode bool from Transaction ID (as per our convention)
    condition_from_id = (transaction_id & 0x00FF) == 0x34  # Example: 0x34 means True

    current_time = datetime.utcnow().time()  # Current time in UTC
    print(f"Current time (UTC): {current_time}")

    # Define the time window (UTC)
    start_time = time(5, 0)  # Start time 05:00 UTC
    end_time = time(23, 55)  # End time 23:55 UTC

    print(f"Time window: {start_time} - {end_time}")

    # Check if within time window and the condition is true
    if start_time <= current_time <= end_time and condition_from_id:
        print("Conditions met, generating CAPTCHA")
        
        # Generate CAPTCHA question and answer
        captcha_question, captcha_answer = generate_captcha()
        
        # Calculate hash of the answer
        captcha_hash = compute_hash(captcha_answer)
        
        # Update DNS with CAPTCHA question and hash
        update_dns_txt_record(f"{captcha_question}|{captcha_hash}")
    else:
        print("Conditions not met, sending failure response")
        # Update DNS with "failed"
        update_dns_txt_record("failed")

    return {
        'statusCode': 200,
        'body': 'DNS record updated successfully'
    }