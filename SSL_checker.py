'''
SSL_checker.py

This file goes through all of the domain names and checks if they are expiring soon. If they are, it will email
a list of people, alerting them of it. 
'''

from SSL_functions import send_email, check_expiration_date, days_until_expiration
from datetime import datetime, timezone
import os
#from dotenv import load_dotenv # Uncomment this for testing

#load_dotenv() # Uncomment this for testing

# load in needed variables
sender_email = os.getenv('SENDER_EMAIL')
sender_password = os.getenv('EMAIL_PASSWORD')
recipient_emails = os.getenv('RECIPIENT_EMAILS')
domain_names = os.getenv('DOMAIN_NAMES')
day_threshold = int(os.getenv('DAY_THRESHOLD'))

# make the domain names into a list
domain_names_list = [domain_name.strip() for domain_name in domain_names.split(",") if domain_name.strip()]

critical_domains = []

today = datetime.now(timezone.utc) # create a timezone aware datetime object for todays date

# First we check all of the domain names that are expiring
for domain_name in domain_names_list:
    expiration_date = check_expiration_date(domain_name) # Get the expiration date
    days_until_exp = days_until_expiration(expiration_date, today) # Get days until expiration

    # Print out the domain name and days until expiration for logging
    print((domain_name, days_until_exp))

    # If the days until expiration is critical, add it to the list
    if  days_until_exp <= day_threshold:
        critical_domains.append((domain_name, days_until_exp))

# Only send the email if there is one or more critical domains
total_critical_domains = len(critical_domains)
if total_critical_domains > 0:
    print(f"The critical domains are {critical_domains}")
    critical_domains.sort(key=lambda x: x[1]) # Sort the critical domains, so the most important ones are at the top

    # Change phrasing based on the number of critical domains
    if total_critical_domains == 1:
        body = "The following domain is expiring soon, please see below:\n\n"
    else:
        body = "The following domains are expiring soon, please see below:\n\n"

    # Make a bulleted list of the critical domains
    for domain, days_left in critical_domains:
        body += f"- {domain}: {days_left} days left\n"
    
    # Add date into the subject so it doesn't become one long email chain
    formatted_date = today.strftime("%m/%d/%y")

    # Add call to action in the subject to bring attention to the email
    subject = f"ACTION NEEDED: Automated SSL expiration msg - {formatted_date}"

    send_email(subject, body, sender_email, sender_password, recipient_emails)

