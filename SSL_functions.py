'''
SSL_functions.py

This file contains all of the functions that will be used to check SSL expiration
'''

import smtplib
import ssl
import socket
from datetime import datetime, timezone

def send_email(subject: str, body: str, sender_email: str, sender_password: str, recipient_emails: str) -> None:
    '''
    Sends an email to a list of recipients.

    Parameters:
    - message: The content of the email to send.
    - sender_email: The email address from which the message will be sent.
    - sender_password: The password for the sender's email account.
    - recipient_emails: A comma-separated string of recipient email addresses.

    Returns:
    - None
    '''
    # Create the list of recipients to send the email to
    recipient_list = [email.strip() for email in recipient_emails.split(",") if email.strip()]

    smtp_payload = f"Subject: {subject}\nTo: {recipient_emails}\n\n{body}" # Craft the smtp payload with the subject and body

    # Send the message with some basic error checking
    try:
        # Connect to the notification email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        # send the email
        server.sendmail(sender_email, recipient_list, smtp_payload)

        server.quit()

    except smtplib.SMTPAuthenticationError:
        print("Failed to authenticate with the SMTP server. Check your email and password.")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"Unexpected error occurred while sending email: {e}")

def check_expiration_date(domain_name: str) -> datetime:
    '''
    Takes domain name and responds with the expiration date

    Parameters:
    - domain_name: the domain name you want to check the expiration date for. (e.g. 'example.com')

    Returns
    - exp_date: the expiration date for the domain name
    '''

    # Set up SSL context for later communication
    context = ssl.create_default_context()

    # Create TCP connection with basic error checking
    try:
        with socket.create_connection((domain_name, 443), timeout=10) as sock:
            # Starts the TLS handshake to get SSL information
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert = ssock.getpeercert() # ask the server for it's SSL cert

                exp_date_str = cert['notAfter']  # get the expiration date from the cert in a string format
                # make it a datetime object for later usage
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc) # explicitly define timezone

                return exp_date
            
    except socket.gaierror:
        print(f"Failed to resolve domain name: {domain_name}")
    except (ssl.SSLError, ConnectionRefusedError) as e:
        print(f"SSL or connection error for {domain_name}: {e}")
    except Exception as e:
        print(f"Unexpected error checking SSL expiration for {domain_name}: {e}")
        
def days_until_expiration(exp_date: datetime, today: datetime) -> int:
    '''
    This function checks if the expiration date happens within ___ days_before

    Parameters:
    - exp_date: the expiration date of the domain name. Must be a timezone aware datetime object.
    - today: timezone aware datetime object. Initialized before and passed to it so you don't keep calculating today throughout
             the script. 

    Returns
    - days_until_exp: Returns an integer number of the days until expiration. 
    '''
    days_until_exp = (exp_date - today).days # Calculate the days until expiration

    return days_until_exp