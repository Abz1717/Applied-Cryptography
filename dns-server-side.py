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
                        'TTL': 5,
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

    # Check if within time window and the condition is true
    if true:
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