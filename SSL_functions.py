'''
SSL_functions.py

This file contains all of the functions that will be used to check SSL expiration
'''

import smtplib
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

    # Crafts the smpt payload with high importance
    smtp_payload = smtp_payload = (
        f"Subject: {subject}\n"
        f"To: {recipient_emails}\n"
        f"X-Priority: 1 (Highest)\n"
        f"X-MSMail-Priority: High\n"
        f"Importance: High\n\n"
        f"{body}"
    )

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

    # Set up SSL context for later communication, it doesn't have to be verified since we own all domains
    context = ssl._create_unverified_context()

    # Create TCP connection with basic error checking
    try:
        with socket.create_connection((domain_name, 443), timeout=10) as sock:
            # Starts the TLS handshake to get SSL information
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                der_cert = ssock.getpeercert(binary_form=True) # ask server for raw cert 
                cert = x509.load_der_x509_certificate(der_cert, default_backend()) # decode the raw cert
                exp_date = cert.not_valid_after_utc # pull out the expiration date 

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